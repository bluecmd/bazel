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
struct NtIoStatusBlock {
  union {
    LONG Status;
    void* Pointer;
  };
  ULONG_PTR Information;
};
typedef LONG(NTAPI* IoctlFn)(HANDLE, HANDLE, void*, void*, NtIoStatusBlock*,
                             ULONG, void*, ULONG, void*, ULONG);

constexpr LONG kStatusAccessDenied = static_cast<LONG>(0xC0000022);
constexpr LONG kStatusObjectNameNotFound = static_cast<LONG>(0xC0000034);
constexpr LONG kStatusObjectPathNotFound = static_cast<LONG>(0xC000003A);
constexpr LONG kStatusFileIsADirectory = static_cast<LONG>(0xC00000BA);
constexpr LONG kStatusNotADirectory = static_cast<LONG>(0xC0000103);

struct ClientFsApi {
  DosToNtPathFn dos_to_nt = nullptr;
  FreeUnicodeStringFn free_string = nullptr;
  IoctlFn ioctl = nullptr;
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
    api.ioctl = reinterpret_cast<IoctlFn>(
        GetProcAddress(ntdll, "NtDeviceIoControlFile"));
    if (api.dos_to_nt == nullptr || api.free_string == nullptr ||
        api.ioctl == nullptr) {
      api.error = L"ntdll lacks RtlDosPathNameToNtPathName_U_WithStatus or NtDeviceIoControlFile";
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
  std::wstring cwd = fs.cmd.substr(0, fs.cmd.find_last_of(L'\\'));
  // DETACHED_PROCESS: no console, hence no conhost.exe, for a process that
  // never runs. Under heavy load the launch has been seen to fail once with
  // ERROR_NO_SYSTEM_RESOURCES; retry a few times before giving up.
  BOOL ok = FALSE;
  DWORD create_error = 0;
  for (int attempt = 0; attempt < 4 && !ok; ++attempt) {
    if (attempt > 0) Sleep(50 << (2 * attempt));  // 200, 800, 3200 ms
    std::wstring cmdline = L"cmd.exe /c exit 0";
    ok = CreateProcessW(
        fs.cmd.c_str(), &cmdline[0], nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | DETACHED_PROCESS | EXTENDED_STARTUPINFO_PRESENT,
        nullptr, cwd.c_str(), &si.StartupInfo, &pi);
    create_error = ok ? 0 : GetLastError();
  }
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
    // Bazel's grants are nearly all files (directories only for enumerate
    // grants), and bfs.sys opens every path itself, failing a type mismatch
    // before it changes anything. So the type is guessed, which saves the
    // GetFileAttributesExW the service makes per path (about a third of
    // the cost), and a mismatch is retried with the other type.
    // Denied paths (few) take the service's way, because bfs.sys accepts a
    // denied path that does not exist with either type.
    DWORD guess = kind == kKindEnumerate ? kTypeDirectory : kTypeFile;
    for (const std::string& utf8 : paths) {
      std::wstring path = Widen(utf8);
      DWORD flags = (kind == kKindReadWrite && IsDriveRoot(path)) ? 0 : 2;
      if (kind == kKindDeny) {
        DWORD type = TypeOf(path);
        if (type == kTypeMissing) {
          missing_deny->push_back(path);
          stats_->missing++;
        } else if (!Send(path, type, kind, flags, error)) {
          return false;
        }
        continue;
      }
      NtUnicodeString nt = {};
      LONG status = fs_.dos_to_nt(path.c_str(), &nt, nullptr, nullptr);
      if (status < 0) {
        *error = L"cannot convert " + path + L" to an NT path: " +
                 Hex(static_cast<uint32_t>(status));
        return false;
      }
      status = Raw(nt, guess, kind, flags);
      if (status == kStatusFileIsADirectory && guess == kTypeFile) {
        status = Raw(nt, kTypeDirectory, kind, flags);
      } else if (status == kStatusNotADirectory && guess == kTypeDirectory) {
        status = Raw(nt, kTypeFile, kind, flags);
      }
      fs_.free_string(&nt);
      if (status >= 0) {
        stats_->applied++;
        continue;
      }
      if (status == kStatusObjectNameNotFound ||
          status == kStatusObjectPathNotFound) {
        // The service skips a path that does not exist; a missing denied path
        // is retried as a directory after all others.
        if (missing_deny != nullptr) missing_deny->push_back(path);
        stats_->missing++;
        continue;
      }
      // Anything else: exactly what the service does.
      DWORD type = TypeOf(path);
      if (type == kTypeMissing) {
        if (missing_deny != nullptr) missing_deny->push_back(path);
        stats_->missing++;
        continue;
      }
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

  // One set-policy request; returns the NTSTATUS.
  LONG Raw(const NtUnicodeString& nt, DWORD type, DWORD kind, DWORD flags) {
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
    NtIoStatusBlock iosb = {};
    return fs_.ioctl(fs_.bfs, nullptr, nullptr, nullptr, &iosb, kBfsSetPolicy,
                     &request, sizeof(request), nullptr, 0);
  }

  // A set-policy request with the service's error handling.
  bool Send(const std::wstring& path, DWORD type, DWORD kind, DWORD flags,
            std::wstring* error) {
    NtUnicodeString nt = {};
    LONG status = fs_.dos_to_nt(path.c_str(), &nt, nullptr, nullptr);
    if (status < 0) {
      *error = L"cannot convert " + path + L" to an NT path: " +
               Hex(static_cast<uint32_t>(status));
      return false;
    }
    status = Raw(nt, type, kind, flags);
    fs_.free_string(&nt);
    if (status >= 0) {
      stats_->applied++;
      return true;
    }
    if (status == kStatusAccessDenied && kind != kKindDeny) {
      // bfs.sys opens the path itself; the service then skips paths the user
      // could not read anyway and fails on the others. Same here.
      if (!UserCanRead(path)) {
        stats_->missing++;
        return true;
      }
    }
    *error = L"bfs.sys refused the policy for " + path + L": status " +
             Hex(static_cast<uint32_t>(status));
    return false;
  }

  const ClientFsApi& fs_;
  HANDLE token_;
  CreateStats* stats_;
};

// The token of every kClient environment, to apply and remove its policy.
std::mutex client_tokens_mu;
std::unordered_map<HANDLE, HANDLE>* client_tokens =
    new std::unordered_map<HANDLE, HANDLE>();

HANDLE ClientToken(HANDLE env) {
  std::lock_guard<std::mutex> lock(client_tokens_mu);
  auto it = client_tokens->find(env);
  return it == client_tokens->end() ? nullptr : it->second;
}

// Creates the (empty) bfs.sys policy entry of `token`, in memory if the
// driver supports it. Without Feature_BfsInMemoryPolicies the request fails
// and the first set-policy request creates a file-backed entry instead, as
// it does for the service.
bool CreatePolicyEntry(const ClientFsApi& fs, HANDLE token) {
  struct {
    HANDLE token;
    uint32_t flags;
    uint32_t pad;
  } entry = {token, 1, 0};
  DWORD returned = 0;
  return DeviceIoControl(fs.bfs, kBfsCreatePolicyEntry, &entry, sizeof(entry),
                         nullptr, 0, &returned, nullptr) != 0;
}

void DeletePolicyEntry(const ClientFsApi& fs, HANDLE token) {
  DWORD returned = 0;
  DeviceIoControl(fs.bfs, kBfsDeletePolicyEntry, &token, sizeof(token), nullptr,
                  0, &returned, nullptr);
}

HANDLE CreateServiceEnvironment(const Api& api, const Spec& spec,
                                std::wstring* error) {
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

}  // namespace

HANDLE CreateBlankEnvironment(const Spec& spec, std::wstring* error,
                              CreateStats* stats) {
  const Api& api = GetApi();
  if (api.create == nullptr) {
    *error = api.error;
    return nullptr;
  }
  CreateStats local_stats;
  if (stats == nullptr) stats = &local_stats;
  const ClientFsApi& fs = GetClientFsApi();
  if (!fs.error.empty()) {
    *error = L"client-side filesystem policy unavailable: " + fs.error;
    return nullptr;
  }
  Spec blank;
  blank.disallow_win32k_system_calls = spec.disallow_win32k_system_calls;
  blank.ui_restrictions = spec.ui_restrictions;
  blank.allow_network = spec.allow_network;
  HANDLE env = CreateServiceEnvironment(api, blank, error);
  if (env == nullptr) return nullptr;
  auto t0 = std::chrono::steady_clock::now();
  HANDLE token = EnvironmentToken(fs, env, error);
  stats->token_ms = MsSince(t0);
  if (token == nullptr) {
    api.close(env);
    return nullptr;
  }
  stats->in_memory = CreatePolicyEntry(fs, token);
  std::lock_guard<std::mutex> lock(client_tokens_mu);
  (*client_tokens)[env] = token;
  return env;
}

bool ApplyFilesystem(HANDLE env, const Spec& spec, std::wstring* error,
                     CreateStats* stats) {
  CreateStats local_stats;
  if (stats == nullptr) stats = &local_stats;
  HANDLE token = ClientToken(env);
  if (token == nullptr) {
    *error = L"not an environment created by CreateBlankEnvironment";
    return false;
  }
  auto t0 = std::chrono::steady_clock::now();
  ClientFsApplier applier(GetClientFsApi(), token, stats);
  bool ok = applier.Apply(spec, error);
  stats->apply_ms = MsSince(t0);
  return ok;
}

bool ClearFilesystem(HANDLE env, std::wstring* error) {
  HANDLE token = ClientToken(env);
  if (token == nullptr) {
    *error = L"not an environment created by CreateBlankEnvironment";
    return false;
  }
  const ClientFsApi& fs = GetClientFsApi();
  DeletePolicyEntry(fs, token);
  CreatePolicyEntry(fs, token);
  return true;
}

HANDLE CreateEnvironment(const Spec& spec, FsApply fs, std::wstring* error,
                         CreateStats* stats) {
  const Api& api = GetApi();
  if (api.create == nullptr) {
    *error = api.error;
    return nullptr;
  }
  if (fs == FsApply::kService) return CreateServiceEnvironment(api, spec, error);
  HANDLE env = CreateBlankEnvironment(spec, error, stats);
  if (env == nullptr) return nullptr;
  if (!ApplyFilesystem(env, spec, error, stats)) {
    CloseEnvironment(env);
    return nullptr;
  }
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
  if (token != nullptr) {
    // Delete the bfs.sys policy entry before the environment goes away. The
    // service's teardown removes it too, but leaks about three paged-pool
    // allocations (pool tags BfsS, BfsG; ~170 bytes) per granted path in
    // bfs.sys, for environments it applied paths to as much as for ours,
    // whereas the delete request frees them. Measured on 10.0.26100.9549;
    // the leak reaches ~2.3 GB after ~13 M paths, and from then on every
    // environment creation fails with ERROR_NO_SYSTEM_RESOURCES until reboot.
    DeletePolicyEntry(GetClientFsApi(), token);
  }
  api.close(env);
  if (token != nullptr) CloseHandle(token);
}

#endif  // _WIN32

}  // namespace psec
}  // namespace windows
}  // namespace bazel
