// Copyright 2026 The Bazel Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "src/main/native/windows/psec.h"

#include <stdint.h>
#include <string.h>

#include <functional>
#include <mutex>  // NOLINT
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace bazel {
namespace windows {
namespace psec {

namespace {

// A minimal FlatBuffers writer. FlatBuffers are normally built back to front;
// this one writes front to back instead: a table is followed by the objects it
// references, so every uoffset_t points forward as the format requires, and
// the (signed) vtable offset points backwards to the vtable written just
// before the table. Only what ProcessSecurityEnvironment.fbs needs is
// supported: scalars, one inline struct, strings, vectors of strings and
// nested tables. Little-endian hosts only, which is all Windows runs on.
class Writer {
 public:
  size_t Pos() const { return buf_.size(); }

  void Pad(size_t align) {
    while (buf_.size() % align != 0) buf_.push_back(0);
  }

  size_t Reserve(size_t n) {
    size_t p = buf_.size();
    buf_.resize(p + n, 0);
    return p;
  }

  template <typename T>
  void Put(size_t at, T v) {
    memcpy(&buf_[at], &v, sizeof(v));
  }

  void PutBytes(size_t at, const void* data, size_t n) {
    if (n > 0) memcpy(&buf_[at], data, n);
  }

  // Points the uoffset_t at `field` to `target`, which must come later.
  void Link(size_t field, size_t target) {
    Put<uint32_t>(field, static_cast<uint32_t>(target - field));
  }

  size_t String(const std::string& s) {
    Pad(4);
    size_t p = Reserve(4 + s.size() + 1);
    Put<uint32_t>(p, static_cast<uint32_t>(s.size()));
    PutBytes(p + 4, s.data(), s.size());
    return p;
  }

  size_t StringVector(const std::vector<std::string>& v) {
    Pad(4);
    size_t p = Reserve(4 + 4 * v.size());
    Put<uint32_t>(p, static_cast<uint32_t>(v.size()));
    for (size_t i = 0; i < v.size(); ++i) {
      Link(p + 4 + 4 * i, String(v[i]));
    }
    return p;
  }

  std::vector<uint8_t> Release() { return std::move(buf_); }

 private:
  std::vector<uint8_t> buf_;
};

class Table {
 public:
  template <typename T>
  void Scalar(int slot, T value) {
    Field f;
    f.slot = slot;
    f.size = f.align = sizeof(T);
    f.bytes.resize(sizeof(T));
    memcpy(f.bytes.data(), &value, sizeof(T));
    fields_.push_back(std::move(f));
  }

  void Struct(int slot, const void* data, size_t size, size_t align) {
    Field f;
    f.slot = slot;
    f.size = size;
    f.align = align;
    f.bytes.assign(static_cast<const uint8_t*>(data),
                   static_cast<const uint8_t*>(data) + size);
    fields_.push_back(std::move(f));
  }

  // `child` writes the referenced object and returns its position.
  void Ref(int slot, std::function<size_t(Writer*)> child) {
    Field f;
    f.slot = slot;
    f.size = f.align = 4;
    f.child = std::move(child);
    fields_.push_back(std::move(f));
  }

  // Writes vtable, table and then the referenced objects; returns the table's
  // position.
  size_t Write(Writer* w) {
    int max_slot = -1;
    size_t table_align = 4;
    size_t offset = 4;  // soffset_t to the vtable comes first.
    std::vector<size_t> field_offset(fields_.size());
    for (size_t i = 0; i < fields_.size(); ++i) {
      const Field& f = fields_[i];
      if (f.slot > max_slot) max_slot = f.slot;
      if (f.align > table_align) table_align = f.align;
      offset = (offset + f.align - 1) / f.align * f.align;
      field_offset[i] = offset;
      offset += f.size;
    }
    size_t table_size = offset;

    w->Pad(2);
    size_t vtable_size = 4 + 2 * (max_slot + 1);
    size_t vtable = w->Reserve(vtable_size);
    w->Put<uint16_t>(vtable, static_cast<uint16_t>(vtable_size));
    w->Put<uint16_t>(vtable + 2, static_cast<uint16_t>(table_size));
    for (size_t i = 0; i < fields_.size(); ++i) {
      w->Put<uint16_t>(vtable + 4 + 2 * fields_[i].slot,
                       static_cast<uint16_t>(field_offset[i]));
    }

    w->Pad(table_align);
    size_t table = w->Reserve(table_size);
    w->Put<int32_t>(table, static_cast<int32_t>(table - vtable));
    for (size_t i = 0; i < fields_.size(); ++i) {
      if (!fields_[i].child) {
        w->PutBytes(table + field_offset[i], fields_[i].bytes.data(),
                    fields_[i].size);
      }
    }
    for (size_t i = 0; i < fields_.size(); ++i) {
      if (fields_[i].child) {
        w->Link(table + field_offset[i], fields_[i].child(w));
      }
    }
    return table;
  }

 private:
  struct Field {
    int slot;
    size_t size;
    size_t align;
    std::vector<uint8_t> bytes;
    std::function<size_t(Writer*)> child;
  };
  std::vector<Field> fields_;
};

// Schema enums.
constexpr int8_t kFilterDeny = 0;
constexpr int8_t kFilterAllow = 1;

// Root table slots, in schema order.
enum RootSlot {
  kVersion = 0,
  kCapabilities = 1,
  kDisallowWin32k = 2,
  kUiRestrictions = 3,
  kFsReadWrite = 4,
  kFsReadOnly = 5,
  kFsDeny = 6,
  kNetworkPolicy = 7,
  kFsEnumerate = 8,
};

}  // namespace

std::vector<uint8_t> EncodeSpec(const Spec& spec, uint16_t major,
                                uint16_t minor, bool with_ingress) {
  Writer w;
  size_t root_offset = w.Reserve(8);
  w.PutBytes(4, "PSEC", 4);

  Table root;
  uint16_t version[2] = {major, minor};
  root.Struct(kVersion, version, sizeof(version), 2);
  if (spec.allow_network) {
    root.Ref(kCapabilities,
             [](Writer* w) { return w->String("internetClient"); });
  }
  if (spec.disallow_win32k_system_calls) {
    root.Scalar<uint8_t>(kDisallowWin32k, 1);
  }
  if (spec.ui_restrictions != 0) {
    root.Scalar<uint64_t>(kUiRestrictions, spec.ui_restrictions);
  }
  auto paths = [&root](int slot, const std::vector<std::string>& v) {
    if (!v.empty()) {
      root.Ref(slot, [&v](Writer* w) { return w->StringVector(v); });
    }
  };
  paths(kFsReadWrite, spec.read_write);
  paths(kFsReadOnly, spec.read_only);
  paths(kFsDeny, spec.deny);
  bool allow = spec.allow_network;
  root.Ref(kNetworkPolicy, [allow, with_ingress](Writer* w) {
    Table network;
    // NetworkPolicy { proxy, egress, allowed_appcontainer_peer, ingress }
    network.Ref(1, [allow](Writer* w) {
      Table egress;  // EndpointPolicy { default_action, allow, deny }
      egress.Scalar<int8_t>(0, allow ? kFilterAllow : kFilterDeny);
      return egress.Write(w);
    });
    if (with_ingress) {
      network.Ref(3, [](Writer* w) {
        Table ingress;  // IngressPolicy { default_action, host_loopback }
        ingress.Scalar<int8_t>(0, kFilterDeny);
        ingress.Scalar<int8_t>(1, kFilterDeny);
        return ingress.Write(w);
      });
    }
    return network.Write(w);
  });
  if (minor >= 1) {
    paths(kFsEnumerate, spec.enumerate);
  }

  w.Link(root_offset, root.Write(&w));
  w.Pad(8);
  return w.Release();
}

#ifdef _WIN32

namespace {

typedef HRESULT(WINAPI* CreateFn)(const void*, DWORD, DWORD, HANDLE*);
typedef void(WINAPI* CloseFn)(HANDLE);
typedef HRESULT(WINAPI* QuerySupportFn)(UINT64*);
typedef HRESULT(WINAPI* VersionSupportedFn)(DWORD, BYTE*, DWORD*);

struct Api {
  CreateFn create = nullptr;
  CloseFn close = nullptr;
  uint16_t minor = 0;
  bool ingress = false;
  std::wstring error;
};

const Api& GetApi() {
  static Api api;
  static std::once_flag once;
  std::call_once(once, [] {
    HMODULE dll = LoadLibraryExW(L"processmodel.dll", nullptr,
                                 LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (dll == nullptr) {
      api.error =
          L"processmodel.dll not found; process security environments need "
          L"Windows 11 25H2 build 26200.9550 or later";
      return;
    }
    api.create = reinterpret_cast<CreateFn>(
        GetProcAddress(dll, "CreateProcessSecurityEnvironment"));
    api.close = reinterpret_cast<CloseFn>(
        GetProcAddress(dll, "CloseProcessSecurityEnvironment"));
    auto query = reinterpret_cast<QuerySupportFn>(
        GetProcAddress(dll, "QueryProcessSecurityEnvironmentSupport"));
    auto version = reinterpret_cast<VersionSupportedFn>(
        GetProcAddress(dll, "IsProcessSecurityEnvironmentVersionSupported"));
    if (api.create == nullptr || api.close == nullptr || query == nullptr ||
        version == nullptr) {
      api.create = nullptr;
      api.error =
          L"processmodel.dll lacks the process security environment API; "
          L"Windows 11 25H2 build 26200.9550 or later is required";
      return;
    }
    BYTE available = 0;
    DWORD minor = 0;
    HRESULT hr = version(1, &available, &minor);
    // Contract 1.1 adds fs_enumerate. Without it a confined process cannot
    // traverse the directories above its grants, so not even an executable
    // in the execroot can be started; refuse rather than half-work.
    if (FAILED(hr) || !available || minor < 1) {
      std::wstringstream s;
      s << L"process security environment contract 1.1 is not available "
        << L"(hr=0x" << std::hex << static_cast<uint32_t>(hr) << std::dec
        << L", available=" << static_cast<int>(available)
        << L", minor=" << minor
        << L"); Windows 11 25H2 build 26200.9550 or later is required";
      api.create = nullptr;
      api.error = s.str();
      return;
    }
    api.minor = minor > 1 ? 1 : static_cast<uint16_t>(minor);
    UINT64 flags = 0;
    if (SUCCEEDED(query(&flags))) {
      api.ingress = (flags & 0x8) != 0;
    }
  });
  return api;
}

}  // namespace

std::wstring EnsureLoaded() { return GetApi().error; }

HANDLE CreateEnvironment(const Spec& spec, std::wstring* error) {
  const Api& api = GetApi();
  if (api.create == nullptr) {
    *error = api.error;
    return nullptr;
  }
  std::vector<uint8_t> blob = EncodeSpec(spec, 1, api.minor, api.ingress);
  HANDLE env = nullptr;
  HRESULT hr = api.create(blob.data(), static_cast<DWORD>(blob.size()), 0, &env);
  if (FAILED(hr) || env == nullptr) {
    std::wstringstream s;
    s << L"CreateProcessSecurityEnvironment failed: hr=0x" << std::hex
      << static_cast<uint32_t>(hr) << std::dec << L" (" << spec.read_only.size()
      << L" read-only, " << spec.read_write.size() << L" read-write, "
      << spec.enumerate.size() << L" enumerate paths)";
    *error = s.str();
    return nullptr;
  }
  return env;
}

void CloseEnvironment(HANDLE env) {
  const Api& api = GetApi();
  if (env != nullptr && api.close != nullptr) {
    api.close(env);
  }
}

#endif  // _WIN32

}  // namespace psec
}  // namespace windows
}  // namespace bazel
