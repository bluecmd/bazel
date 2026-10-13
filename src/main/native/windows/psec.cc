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

#include <chrono>  // NOLINT
#include <functional>
#include <mutex>  // NOLINT
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <aclapi.h>
#endif

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

namespace {

std::wstring Widen(const std::string& s) {
  if (s.empty()) return std::wstring();
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                              nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &w[0],
                      n);
  return w;
}

std::wstring Hex(uint32_t v) {
  std::wstringstream s;
  s << L"0x" << std::hex << v;
  return s.str();
}

double MsSince(std::chrono::steady_clock::time_point t) {
  return std::chrono::duration<double, std::milli>(
             std::chrono::steady_clock::now() - t)
      .count();
}

// ---------------------------------------------------------------------------
// Client-side filesystem policy (FsApply::kClient).
//
// The AppInfo service applies a spec's paths in
// processmodel!SandboxFilesystem::ApplyFilesystemPolicy: per path a
// GetVolumePathNameW walk (to attach bfs.sys to non-NTFS volumes) and one
// set-policy request to \Device\Bfs. It skips all of that when the spec has
// no paths. bfs.sys keys a policy on {TokenUser, TokenAppContainerSid} of the
// token handle passed in the request, so any process holding an AppContainer
// token of the environment's profile can send the same requests. The child
// processes of the environment hold exactly such a token: we start one
// suspended, take its token, kill it, and apply the paths with it. Reverse
// engineered from processmodel.dll / bfs.sys 10.0.26100.9549, see
// src/main/tools/windows-sandbox-mxc/psec/experiments/fastfs/ on the
// windows-sandbox-psec-exe branch.

// bfs.sys device control codes.
constexpr DWORD kBfsSetPolicy = 0x228004;          // one path
constexpr DWORD kBfsDeletePolicyEntry = 0x228010;  // all paths of a token
constexpr DWORD kBfsCreatePolicyEntry = 0x228014;  // {token, flags}; 1 = in memory

// Policy kinds of kBfsSetPolicy.
constexpr DWORD kKindReadWrite = 1;
constexpr DWORD kKindReadOnly = 2;
constexpr DWORD kKindDeny = 4;
constexpr DWORD kKindEnumerate = 6;

// Object types of kBfsSetPolicy.
constexpr DWORD kTypeMissing = 0;
constexpr DWORD kTypeFile = 1;
constexpr DWORD kTypeDirectory = 2;

struct NtUnicodeString {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
};
typedef LONG(NTAPI* DosToNtPathFn)(PCWSTR, NtUnicodeString*, PWSTR*, void*);
typedef void(NTAPI* FreeUnicodeStringFn)(NtUnicodeString*);

struct ClientFsApi {
  DosToNtPathFn dos_to_nt = nullptr;
  FreeUnicodeStringFn free_string = nullptr;
  HANDLE bfs = INVALID_HANDLE_VALUE;
  std::wstring cmd;  // the probe process image
  std::wstring error;
};

const ClientFsApi& GetClientFsApi() {
  static ClientFsApi api;
  static std::once_flag once;
  std::call_once(once, [] {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    api.dos_to_nt = reinterpret_cast<DosToNtPathFn>(
        GetProcAddress(ntdll, "RtlDosPathNameToNtPathName_U_WithStatus"));
    api.free_string = reinterpret_cast<FreeUnicodeStringFn>(
        GetProcAddress(ntdll, "RtlFreeUnicodeString"));
    if (api.dos_to_nt == nullptr || api.free_string == nullptr) {
      api.error = L"ntdll lacks RtlDosPathNameToNtPathName_U_WithStatus";
      return;
    }
    // One handle for the whole process; requests on it are synchronous and
    // bfs.sys serializes its policy table internally.
    api.bfs = CreateFileW(L"\\\\.\\GLOBALROOT\\Device\\Bfs",
                          GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          nullptr, OPEN_EXISTING, 0, nullptr);
    if (api.bfs == INVALID_HANDLE_VALUE) {
      api.error = L"cannot open \\Device\\Bfs: error " +
                  std::to_wstring(GetLastError());
      return;
    }
    WCHAR sys[MAX_PATH];
    UINT n = GetSystemDirectoryW(sys, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
      api.error = L"GetSystemDirectoryW failed";
      return;
    }
    api.cmd = std::wstring(sys, n) + L"\\cmd.exe";
  });
  return api;
}

// Starts a suspended process in `env` and returns its primary token: an
// AppContainer token of the environment's profile, carrying the capabilities
// the service gave it (bfs.sys requires AgenticAppContainer among them).
HANDLE EnvironmentToken(const ClientFsApi& fs, HANDLE env,
                        std::wstring* error) {
  SIZE_T size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
  std::vector<uint8_t> attr_buf(size);
  auto attrs =
      reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
  if (!InitializeProcThreadAttributeList(attrs, 1, 0, &size)) {
    *error = L"InitializeProcThreadAttributeList: error " +
             std::to_wstring(GetLastError());
    return nullptr;
  }
  HANDLE env_value = env;
  if (!UpdateProcThreadAttribute(attrs, 0,
                                 kProcThreadAttributeSecurityEnvironment,
                                 &env_value, sizeof(env_value), nullptr,
                                 nullptr)) {
    *error = L"UpdateProcThreadAttribute: error " +
             std::to_wstring(GetLastError());
    DeleteProcThreadAttributeList(attrs);
    return nullptr;
  }
  STARTUPINFOEXW si = {};
  si.StartupInfo.cb = sizeof(si);
  si.lpAttributeList = attrs;
  PROCESS_INFORMATION pi = {};
  std::wstring cmdline = L"cmd.exe /c exit 0";
  std::wstring cwd = fs.cmd.substr(0, fs.cmd.find_last_of(L'\\'));
  BOOL ok = CreateProcessW(
      fs.cmd.c_str(), &cmdline[0], nullptr, nullptr, FALSE,
      CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
      nullptr, cwd.c_str(), &si.StartupInfo, &pi);
  DWORD create_error = GetLastError();
  DeleteProcThreadAttributeList(attrs);
  if (!ok) {
    *error = L"starting the token probe in the environment: error " +
             std::to_wstring(create_error);
    return nullptr;
  }
  HANDLE token = nullptr;
  if (!OpenProcessToken(pi.hProcess, TOKEN_QUERY, &token)) {
    *error = L"OpenProcessToken of the token probe: error " +
             std::to_wstring(GetLastError());
    token = nullptr;
  }
  TerminateProcess(pi.hProcess, 0);
  WaitForSingleObject(pi.hProcess, 5000);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return token;
}

// processmodel's CheckFileAccessRights: could the user read `path` anyway?
bool UserCanRead(const std::wstring& path) {
  HANDLE process_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY,
                        &process_token)) {
    return false;
  }
  HANDLE token = nullptr;
  BOOL dup = DuplicateToken(process_token, SecurityImpersonation, &token);
  CloseHandle(process_token);
  if (!dup) return false;
  PSECURITY_DESCRIPTOR sd = nullptr;
  bool result = false;
  if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
                            OWNER_SECURITY_INFORMATION |
                                GROUP_SECURITY_INFORMATION |
                                DACL_SECURITY_INFORMATION,
                            nullptr, nullptr, nullptr, nullptr,
                            &sd) == ERROR_SUCCESS) {
    GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                               FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    uint8_t privileges[sizeof(PRIVILEGE_SET) + 8 * sizeof(LUID_AND_ATTRIBUTES)];
    DWORD privileges_size = sizeof(privileges);
    DWORD granted = 0;
    BOOL status = FALSE;
    result = AccessCheck(sd, token, GENERIC_READ, &mapping,
                         reinterpret_cast<PPRIVILEGE_SET>(privileges),
                         &privileges_size, &granted, &status) &&
             status;
    LocalFree(sd);
  }
  CloseHandle(token);
  return result;
}

DWORD TypeOf(const std::wstring& path) {
  WIN32_FILE_ATTRIBUTE_DATA data;
  if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) {
    return kTypeMissing;
  }
  return (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? kTypeDirectory
                                                            : kTypeFile;
}

bool IsDriveRoot(const std::wstring& path) {
  return path.size() == 3 && path[1] == L':' && path[2] == L'\\';
}

class ClientFsApplier {
 public:
  ClientFsApplier(const ClientFsApi& fs, HANDLE token, CreateStats* stats)
      : fs_(fs), token_(token), stats_(stats) {}

  // processmodel!SandboxFilesystem::ApplyFilesystem, path for path.
  bool Apply(const Spec& spec, std::wstring* error) {
    struct {
      HANDLE token;
      uint32_t flags;
      uint32_t pad;
    } entry = {token_, 1, 0};
    DWORD returned = 0;
    stats_->in_memory =
        DeviceIoControl(fs_.bfs, kBfsCreatePolicyEntry, &entry, sizeof(entry),
                        nullptr, 0, &returned, nullptr) != 0;
    // Without Feature_BfsInMemoryPolicies the request fails and the first
    // set-policy request creates a file-backed entry, as for the service.
    std::vector<std::wstring> missing_deny;
    return Vector(spec.read_write, kKindReadWrite, nullptr, error) &&
           Vector(spec.read_only, kKindReadOnly, nullptr, error) &&
           Vector(spec.enumerate, kKindEnumerate, nullptr, error) &&
           Vector(spec.deny, kKindDeny, &missing_deny, error) &&
           MissingDeny(missing_deny, error);
  }

 private:
  bool Vector(const std::vector<std::string>& paths, DWORD kind,
              std::vector<std::wstring>* missing_deny, std::wstring* error) {
    for (const std::string& utf8 : paths) {
      std::wstring path = Widen(utf8);
      DWORD type = TypeOf(path);
      if (type == kTypeMissing) {
        // The service skips a path that does not exist; a missing denied path
        // is retried as a directory after all others.
        if (missing_deny != nullptr) missing_deny->push_back(path);
        stats_->missing++;
        continue;
      }
      DWORD flags = (kind == kKindReadWrite && IsDriveRoot(path)) ? 0 : 2;
      if (!Send(path, type, kind, flags, error)) return false;
    }
    return true;
  }

  bool MissingDeny(const std::vector<std::wstring>& paths,
                   std::wstring* error) {
    for (const std::wstring& path : paths) {
      DWORD type = TypeOf(path);
      if (!Send(path, type == kTypeMissing ? kTypeDirectory : type, kKindDeny,
                2, error)) {
        return false;
      }
    }
    return true;
  }

  bool Send(const std::wstring& path, DWORD type, DWORD kind, DWORD flags,
            std::wstring* error) {
    NtUnicodeString nt = {};
    LONG status = fs_.dos_to_nt(path.c_str(), &nt, nullptr, nullptr);
    if (status < 0) {
      *error = L"cannot convert " + path + L" to an NT path: " +
               Hex(static_cast<uint32_t>(status));
      return false;
    }
    // BfsProcessSetPolicyRequest's 0x30-byte input.
    struct {
      HANDLE token;    // +0x00
      DWORD type;      // +0x08
      DWORD kind;      // +0x0C
      DWORD flags;     // +0x10
      DWORD pad1;      // +0x14
      NtUnicodeString name;  // +0x18 (Length, MaximumLength, pad, Buffer)
      DWORD operation;  // +0x28: 0 = add or modify
      DWORD pad2;
    } request = {token_, type, kind, flags, 0, nt, 0, 0};
    static_assert(sizeof(request) == 0x30, "bfs set-policy request layout");
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(fs_.bfs, kBfsSetPolicy, &request,
                              sizeof(request), nullptr, 0, &returned, nullptr);
    DWORD last = GetLastError();
    fs_.free_string(&nt);
    if (ok) {
      stats_->applied++;
      return true;
    }
    if (last == ERROR_ACCESS_DENIED && kind != kKindDeny) {
      // bfs.sys opens the path itself; the service then skips paths the user
      // could not read anyway and fails on the others. Same here.
      if (!UserCanRead(path)) {
        stats_->missing++;
        return true;
      }
    }
    *error = L"bfs.sys refused the policy for " + path + L": error " +
             std::to_wstring(last);
    return false;
  }

  const ClientFsApi& fs_;
  HANDLE token_;
  CreateStats* stats_;
};

// The token of every kClient environment, to remove its policy on close.
std::mutex client_tokens_mu;
std::unordered_map<HANDLE, HANDLE>* client_tokens =
    new std::unordered_map<HANDLE, HANDLE>();

}  // namespace

HANDLE CreateEnvironment(const Spec& spec, FsApply fs, std::wstring* error,
                         CreateStats* stats) {
  const Api& api = GetApi();
  if (api.create == nullptr) {
    *error = api.error;
    return nullptr;
  }
  CreateStats local_stats;
  if (stats == nullptr) stats = &local_stats;
  const ClientFsApi* client_fs = nullptr;
  Spec service_spec;
  const Spec* encoded = &spec;
  if (fs == FsApply::kClient) {
    client_fs = &GetClientFsApi();
    if (!client_fs->error.empty()) {
      *error = L"client-side filesystem policy unavailable: " +
               client_fs->error;
      return nullptr;
    }
    service_spec.disallow_win32k_system_calls =
        spec.disallow_win32k_system_calls;
    service_spec.ui_restrictions = spec.ui_restrictions;
    service_spec.allow_network = spec.allow_network;
    encoded = &service_spec;
  }
  std::vector<uint8_t> blob = EncodeSpec(*encoded, 1, api.minor, api.ingress);
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
  if (client_fs == nullptr) return env;

  auto t0 = std::chrono::steady_clock::now();
  HANDLE token = EnvironmentToken(*client_fs, env, error);
  stats->token_ms = MsSince(t0);
  if (token == nullptr) {
    api.close(env);
    return nullptr;
  }
  t0 = std::chrono::steady_clock::now();
  ClientFsApplier applier(*client_fs, token, stats);
  bool ok = applier.Apply(spec, error);
  stats->apply_ms = MsSince(t0);
  if (!ok) {
    DWORD returned = 0;
    DeviceIoControl(client_fs->bfs, kBfsDeletePolicyEntry, &token,
                    sizeof(token), nullptr, 0, &returned, nullptr);
    CloseHandle(token);
    api.close(env);
    return nullptr;
  }
  std::lock_guard<std::mutex> lock(client_tokens_mu);
  (*client_tokens)[env] = token;
  return env;
}

void CloseEnvironment(HANDLE env) {
  const Api& api = GetApi();
  if (env == nullptr || api.close == nullptr) return;
  HANDLE token = nullptr;
  {
    std::lock_guard<std::mutex> lock(client_tokens_mu);
    auto it = client_tokens->find(env);
    if (it != client_tokens->end()) {
      token = it->second;
      client_tokens->erase(it);
    }
  }
  api.close(env);
  if (token != nullptr) {
    // The service removes the bfs.sys entry of the profile when it tears the
    // environment down; remove it ourselves too, in case it only does so for
    // policies it applied. Failure (already gone) is fine.
    DWORD returned = 0;
    DeviceIoControl(GetClientFsApi().bfs, kBfsDeletePolicyEntry, &token,
                    sizeof(token), nullptr, 0, &returned, nullptr);
    CloseHandle(token);
  }
}

#endif  // _WIN32

}  // namespace psec
}  // namespace windows
}  // namespace bazel
