// BazelSandbox.exe on the Windows process security environment primitive
// (PSEC, `CreateProcessSecurityEnvironment` in processmodel.dll), with no MXC
// SDK. Implements the contract Bazel's WindowsSandboxedSpawnRunner emits:
//
//   BazelSandbox [-W cwd] [-T timeout_s] [-t kill_delay_s] [-l stdout] [-L stderr]
//                (-w rw)* (-r ro)* (-b denied)* [-D] [@params]* -- cmd args...
//
// `@params` names a UTF-8 file with one argument per line, used by the runner
// when the path lists would exceed the command-line limit.
//
// The policy rules are the ones the Rust MXC adapter (../src/main.rs) had to
// discover; the FlatBuffer encoder and API declarations are lifted from
// src/main/native/windows/psec.cc on branch windows-sandbox-psec-jni. See
// README.md and GAPS-all-actions-sandboxed.md next to this file.
//
// Knobs (Bazel scrubs the action environment, so they come through
// --action_env):
//
//   BAZEL_MXC_EXTRA_RO=<p>;<p>   extra read-only roots (toolchains outside the execroot)
//   BAZEL_PSEC_EXTRA_RW=<p>;<p>  extra read-write roots
//   BAZEL_MXC_DIR_GRANTS=1       grant the directory of each read-only input instead of the file
//   BAZEL_MXC_NO_ENUM=1          do not list the cwd and grant ancestors as enumerate-only
//   BAZEL_MXC_NO_UI=1            keep the Win32k lockdown (USER32 importers then fail)
//   BAZEL_PSEC_UI_MASK=<hex>     ui_restrictions mask (default 0x3DE, MXC's "desktop" isolation)
//   BAZEL_PSEC_NET=1             allow network egress (+ internetClient capability)
//   BAZEL_PSEC_CAPS=<a,b>        extra AppContainer capabilities (CSV) to put in the spec
//   BAZEL_PSEC_NO_INGRESS=1      do not write the ingress table
//   BAZEL_PSEC_NO_TMPDIR=1       do not set TMPDIR (Python's tempfile then uses the AC\Temp redirect)
//   BAZEL_PSEC_SHORT_TMP=<dir>   use <dir>\<pid> as TMP/TEMP/TMPDIR (granted rw, deleted afterwards)
//   BAZEL_PSEC_NO_SANDBOX=1      run the command without an environment (A/B comparison)
//   BAZEL_PSEC_NO_WIDEN=1        do not widen missing outputs to their directory
//   BAZEL_PSEC_LOG=<file>        append policy, command and result to <file>
//   BAZEL_MXC_TIMING=<file>      append prep/spawn/wait ms and grant counts
//   BAZEL_MXC_DEBUG=1 (or -D)    print the effective policy to stderr
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <userenv.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

using Clock = std::chrono::steady_clock;

double MsSince(Clock::time_point t0) {
  return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

std::string ToUtf8(const std::wstring& w) {
  if (w.empty()) return std::string();
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
  std::string s(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
  return s;
}

std::wstring FromUtf8(const std::string& s) {
  if (s.empty()) return std::wstring();
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
  return w;
}

void Err(const wchar_t* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fwprintf(stderr, L"BazelSandbox: ");
  vfwprintf(stderr, fmt, ap);
  fwprintf(stderr, L"\n");
  fflush(stderr);
  va_end(ap);
}

std::optional<std::wstring> GetEnv(const wchar_t* name) {
  DWORD n = GetEnvironmentVariableW(name, nullptr, 0);
  if (n == 0) return std::nullopt;
  std::wstring v(n, L'\0');
  DWORD m = GetEnvironmentVariableW(name, &v[0], n);
  v.resize(m);
  return v;
}

bool EnvSet(const wchar_t* name) {
  auto v = GetEnv(name);
  return v && !v->empty() && *v != L"0";
}

std::vector<std::wstring> SplitSemi(const std::wstring& s) {
  std::vector<std::wstring> out;
  size_t start = 0;
  while (start <= s.size()) {
    size_t p = s.find(L';', start);
    if (p == std::wstring::npos) p = s.size();
    if (p > start) out.push_back(s.substr(start, p - start));
    start = p + 1;
  }
  return out;
}

// Comparison key: lower case, backslashes, no trailing separator (except on a
// drive root such as `C:\`).
std::wstring Key(const std::wstring& p) {
  std::wstring k = p;
  for (auto& c : k) {
    if (c == L'/') c = L'\\';
    else c = (wchar_t)towlower(c);
  }
  while (k.size() > 3 && k.back() == L'\\') k.pop_back();
  return k;
}

std::wstring Backslashes(std::wstring p) {
  for (auto& c : p) if (c == L'/') c = L'\\';
  return p;
}

bool IsAbsolute(const std::wstring& p) {
  return (p.size() >= 3 && iswalpha(p[0]) && p[1] == L':' && (p[2] == L'\\' || p[2] == L'/')) ||
         (p.size() >= 2 && (p[0] == L'\\' || p[0] == L'/') && (p[1] == L'\\' || p[1] == L'/'));
}

// Parent directory, or empty for a drive root.
std::wstring Parent(const std::wstring& p) {
  std::wstring k = Backslashes(p);
  while (k.size() > 3 && k.back() == L'\\') k.pop_back();
  size_t pos = k.find_last_of(L'\\');
  if (pos == std::wstring::npos) return L"";
  if (pos == 2 && k.size() > 3 && k[1] == L':') return k.substr(0, 3);  // C:\x -> C:\ .
  if (pos <= 2) return L"";
  return k.substr(0, pos);
}

// Paths in Bazel's tree exceed MAX_PATH (maven artifacts under the repository
// contents cache); the \\?\ prefix makes the Win32 calls take them.
std::wstring LongPath(const std::wstring& p) {
  return IsAbsolute(p) && p.compare(0, 4, L"\\\\?\\") != 0 && p.compare(0, 2, L"\\\\") != 0 ? L"\\\\?\\" + Backslashes(p) : p;
}
DWORD Attrs(const std::wstring& p) { return GetFileAttributesW(LongPath(p).c_str()); }
bool Exists(const std::wstring& p) { return Attrs(p) != INVALID_FILE_ATTRIBUTES; }
bool IsDir(const std::wstring& p) {
  DWORD a = Attrs(p);
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}
bool IsFile(const std::wstring& p) {
  DWORD a = Attrs(p);
  return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

// Is `k` (a key) equal to or inside directory key `d`?
bool Under(const std::wstring& k, const std::wstring& d) {
  if (k == d) return true;
  if (k.size() <= d.size() || k.compare(0, d.size(), d) != 0) return false;
  return d.back() == L'\\' || k[d.size()] == L'\\';
}

// The final (symlink/junction-resolved) path of `p` without `\\?\`; empty if
// it does not exist or resolves to UNC. Cached.
std::wstring FinalPath(const std::wstring& p) {
  static std::unordered_map<std::wstring, std::wstring> cache;
  auto it = cache.find(p);
  if (it != cache.end()) return it->second;
  std::wstring result;
  std::wstring opened = IsAbsolute(p) && p.compare(0, 4, L"\\\\?\\") != 0 ? L"\\\\?\\" + Backslashes(p) : p;
  HANDLE h = CreateFileW(opened.c_str(), FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                         OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (h != INVALID_HANDLE_VALUE) {
    std::vector<wchar_t> buf(1024);
    DWORD n = GetFinalPathNameByHandleW(h, buf.data(), (DWORD)buf.size(), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (n >= buf.size()) {
      buf.resize(n + 1);
      n = GetFinalPathNameByHandleW(h, buf.data(), (DWORD)buf.size(), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    }
    if (n > 0 && n < buf.size()) result.assign(buf.data(), n);
    CloseHandle(h);
    if (result.compare(0, 8, L"\\\\?\\UNC\\") == 0) result.clear();
    else if (result.compare(0, 4, L"\\\\?\\") == 0) result.erase(0, 4);
  }
  cache[p] = result;
  return result;
}

void Dedupe(std::vector<std::wstring>& v) {
  std::unordered_set<std::wstring> seen;
  std::vector<std::wstring> out;
  for (auto& p : v) if (seen.insert(Key(p)).second) out.push_back(p);
  v.swap(out);
}

// Drop entries inside another entry of the same list (sorted keys, one pass).
void PruneNested(std::vector<std::wstring>& v) {
  std::vector<std::pair<std::wstring, std::wstring>> keyed;
  for (auto& p : v) keyed.emplace_back(Key(p), p);
  std::sort(keyed.begin(), keyed.end());
  std::vector<std::wstring> out;
  std::wstring last;
  for (auto& kp : keyed) {
    if (!last.empty() && Under(kp.first, last)) continue;
    last = kp.first;
    out.push_back(kp.second);
  }
  v.swap(out);
}

// Windows command line from argv, per the CRT's parsing rules.
void QuoteArg(std::wstring& out, const std::wstring& a) {
  if (!a.empty() && a.find_first_of(L" \t\"") == std::wstring::npos) {
    out += a;
    return;
  }
  out += L'"';
  size_t bs = 0;
  for (wchar_t c : a) {
    if (c == L'\\') {
      bs++;
    } else if (c == L'"') {
      out.append(bs * 2 + 1, L'\\');
      out += L'"';
      bs = 0;
    } else {
      out.append(bs, L'\\');
      out += c;
      bs = 0;
    }
  }
  out.append(bs * 2, L'\\');
  out += L'"';
}

void AppendFile(const std::wstring& path, const std::string& text) {
  HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return;
  DWORD w = 0;
  WriteFile(h, text.data(), (DWORD)text.size(), &w, nullptr);
  CloseHandle(h);
}

void RemoveTree(const std::wstring& dir) {
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      std::wstring name = fd.cFileName;
      if (name == L"." || name == L"..") continue;
      std::wstring full = dir + L"\\" + name;
      if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        RemoveTree(full);
      } else {
        SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryW(full.c_str());
        else DeleteFileW(full.c_str());
      }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
  RemoveDirectoryW(dir.c_str());
}

// ---------------------------------------------------------------------------
// The "PSEC" FlatBuffer (ProcessSecurityEnvironment.fbs), written front to
// back with a minimal writer: a table is followed by the objects it
// references, so every uoffset_t points forward and the soffset_t back to
// the vtable written just before the table. From psec.cc (JNI branch).
// ---------------------------------------------------------------------------

class Writer {
 public:
  size_t Pos() const { return buf_.size(); }
  void Pad(size_t align) { while (buf_.size() % align != 0) buf_.push_back(0); }
  size_t Reserve(size_t n) { size_t p = buf_.size(); buf_.resize(p + n, 0); return p; }
  template <typename T> void Put(size_t at, T v) { memcpy(&buf_[at], &v, sizeof(v)); }
  void PutBytes(size_t at, const void* data, size_t n) { if (n > 0) memcpy(&buf_[at], data, n); }
  void Link(size_t field, size_t target) { Put<uint32_t>(field, (uint32_t)(target - field)); }
  size_t String(const std::string& s) {
    Pad(4);
    size_t p = Reserve(4 + s.size() + 1);
    Put<uint32_t>(p, (uint32_t)s.size());
    PutBytes(p + 4, s.data(), s.size());
    return p;
  }
  size_t StringVector(const std::vector<std::string>& v) {
    Pad(4);
    size_t p = Reserve(4 + 4 * v.size());
    Put<uint32_t>(p, (uint32_t)v.size());
    for (size_t i = 0; i < v.size(); ++i) Link(p + 4 + 4 * i, String(v[i]));
    return p;
  }
  std::vector<uint8_t> Release() { return std::move(buf_); }

 private:
  std::vector<uint8_t> buf_;
};

class Table {
 public:
  template <typename T> void Scalar(int slot, T value) {
    Field f; f.slot = slot; f.size = f.align = sizeof(T);
    f.bytes.resize(sizeof(T)); memcpy(f.bytes.data(), &value, sizeof(T));
    fields_.push_back(std::move(f));
  }
  void Struct(int slot, const void* data, size_t size, size_t align) {
    Field f; f.slot = slot; f.size = size; f.align = align;
    f.bytes.assign((const uint8_t*)data, (const uint8_t*)data + size);
    fields_.push_back(std::move(f));
  }
  void Ref(int slot, std::function<size_t(Writer*)> child) {
    Field f; f.slot = slot; f.size = f.align = 4; f.child = std::move(child);
    fields_.push_back(std::move(f));
  }
  size_t Write(Writer* w) {
    int max_slot = -1;
    size_t table_align = 4, offset = 4;
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
    w->Put<uint16_t>(vtable, (uint16_t)vtable_size);
    w->Put<uint16_t>(vtable + 2, (uint16_t)table_size);
    for (size_t i = 0; i < fields_.size(); ++i)
      w->Put<uint16_t>(vtable + 4 + 2 * fields_[i].slot, (uint16_t)field_offset[i]);
    w->Pad(table_align);
    size_t table = w->Reserve(table_size);
    w->Put<int32_t>(table, (int32_t)(table - vtable));
    for (size_t i = 0; i < fields_.size(); ++i)
      if (!fields_[i].child) w->PutBytes(table + field_offset[i], fields_[i].bytes.data(), fields_[i].size);
    for (size_t i = 0; i < fields_.size(); ++i)
      if (fields_[i].child) w->Link(table + field_offset[i], fields_[i].child(w));
    return table;
  }

 private:
  struct Field {
    int slot; size_t size; size_t align;
    std::vector<uint8_t> bytes;
    std::function<size_t(Writer*)> child;
  };
  std::vector<Field> fields_;
};

struct Spec {
  std::vector<std::string> read_write, read_only, deny, enumerate;
  std::string capabilities;  // CSV
  bool disallow_win32k = false;
  uint64_t ui_restrictions = 0x3DE;
  bool allow_network = false;
};

std::vector<uint8_t> EncodeSpec(const Spec& spec, uint16_t major, uint16_t minor, bool with_ingress) {
  enum { kVersion = 0, kCapabilities, kDisallowWin32k, kUiRestrictions, kFsReadWrite, kFsReadOnly,
         kFsDeny, kNetworkPolicy, kFsEnumerate };
  const int8_t kDeny = 0, kAllow = 1;
  Writer w;
  size_t root_offset = w.Reserve(8);
  w.PutBytes(4, "PSEC", 4);
  Table root;
  uint16_t version[2] = {major, minor};
  root.Struct(kVersion, version, sizeof(version), 2);
  if (!spec.capabilities.empty())
    root.Ref(kCapabilities, [&](Writer* w) { return w->String(spec.capabilities); });
  if (spec.disallow_win32k) root.Scalar<uint8_t>(kDisallowWin32k, 1);
  if (spec.ui_restrictions != 0) root.Scalar<uint64_t>(kUiRestrictions, spec.ui_restrictions);
  auto paths = [&root](int slot, const std::vector<std::string>& v) {
    if (!v.empty()) root.Ref(slot, [&v](Writer* w) { return w->StringVector(v); });
  };
  paths(kFsReadWrite, spec.read_write);
  paths(kFsReadOnly, spec.read_only);
  paths(kFsDeny, spec.deny);
  bool allow = spec.allow_network;
  root.Ref(kNetworkPolicy, [allow, with_ingress, kDeny, kAllow](Writer* w) {
    Table network;  // NetworkPolicy { proxy, egress, allowed_appcontainer_peer, ingress }
    network.Ref(1, [allow, kDeny, kAllow](Writer* w) {
      Table egress;  // EndpointPolicy { default_action, allow, deny }
      egress.Scalar<int8_t>(0, allow ? kAllow : kDeny);
      return egress.Write(w);
    });
    if (with_ingress) {
      network.Ref(3, [kDeny](Writer* w) {
        Table ingress;  // IngressPolicy { default_action, host_loopback }
        ingress.Scalar<int8_t>(0, kDeny);
        ingress.Scalar<int8_t>(1, kDeny);
        return ingress.Write(w);
      });
    }
    return network.Write(w);
  });
  if (minor >= 1) paths(kFsEnumerate, spec.enumerate);
  w.Link(root_offset, root.Write(&w));
  w.Pad(8);
  return w.Release();
}

// ---------------------------------------------------------------------------
// processmodel.dll (not in any SDK header; signatures from MXC's FFI and the
// processmodel.pdb symbols)
// ---------------------------------------------------------------------------

typedef HRESULT(WINAPI* CreateFn)(const void*, DWORD, DWORD, HANDLE*);
typedef void(WINAPI* CloseFn)(HANDLE);
typedef HRESULT(WINAPI* QuerySupportFn)(UINT64*);
typedef HRESULT(WINAPI* VersionSupportedFn)(DWORD, BYTE*, DWORD*);
constexpr DWORD_PTR kProcThreadAttributeSecurityEnvironment = 35 | 0x00020000;  // | PROC_THREAD_ATTRIBUTE_INPUT

struct Api {
  CreateFn create = nullptr;
  CloseFn close = nullptr;
  uint16_t minor = 0;
  UINT64 support = 0;
  std::wstring error;
};

Api LoadApi() {
  Api api;
  HMODULE dll = LoadLibraryExW(L"processmodel.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!dll) { api.error = L"processmodel.dll not found; Windows 11 25H2 26200.9550+ required"; return api; }
  api.create = (CreateFn)GetProcAddress(dll, "CreateProcessSecurityEnvironment");
  api.close = (CloseFn)GetProcAddress(dll, "CloseProcessSecurityEnvironment");
  auto query = (QuerySupportFn)GetProcAddress(dll, "QueryProcessSecurityEnvironmentSupport");
  auto version = (VersionSupportedFn)GetProcAddress(dll, "IsProcessSecurityEnvironmentVersionSupported");
  if (!api.create || !api.close || !query || !version) {
    api.create = nullptr;
    api.error = L"processmodel.dll lacks the process security environment API";
    return api;
  }
  BYTE available = 0; DWORD minor = 0;
  HRESULT hr = version(1, &available, &minor);
  if (FAILED(hr) || !available || minor < 1) {
    wchar_t buf[256];
    swprintf(buf, 256, L"PSEC contract 1.1 not available (hr=0x%08X available=%u minor=%u)", (unsigned)hr, available, (unsigned)minor);
    api.create = nullptr; api.error = buf;
    return api;
  }
  api.minor = 1;
  query(&api.support);
  return api;
}

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

struct Args {
  std::wstring cwd, stdoutPath, stderrPath;
  std::optional<DWORD> timeoutMs;
  std::vector<std::wstring> rw, ro, deny, cmd;
  bool debug = false;
};

const wchar_t* kUsage = L"usage: BazelSandbox [-W cwd] [-T s] [-t s] [-l out] [-L err] [-w p]* [-r p]* [-b p]* [-D] [@params]* -- cmd...";

bool ExpandParams(const std::vector<std::wstring>& raw, std::vector<std::wstring>& out) {
  bool after = false;
  for (const auto& a : raw) {
    if (after || a == L"--") { after = true; out.push_back(a); continue; }
    if (a.size() > 1 && a[0] == L'@') {
      std::wstring file = a.substr(1);
      HANDLE h = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
      if (h == INVALID_HANDLE_VALUE) { Err(L"cannot read params file %s: %u", file.c_str(), GetLastError()); return false; }
      LARGE_INTEGER sz; GetFileSizeEx(h, &sz);
      std::string text((size_t)sz.QuadPart, '\0');
      DWORD rd = 0; size_t got = 0;
      while (got < text.size() && ReadFile(h, &text[got], (DWORD)(text.size() - got), &rd, nullptr) && rd > 0) got += rd;
      CloseHandle(h);
      std::wstring w = FromUtf8(text);
      size_t s = 0;
      while (s < w.size()) {
        size_t e = w.find(L'\n', s);
        if (e == std::wstring::npos) e = w.size();
        std::wstring line = w.substr(s, e - s);
        while (!line.empty() && line.back() == L'\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
        s = e + 1;
      }
    } else {
      out.push_back(a);
    }
  }
  return true;
}

bool ParseArgs(int argc, wchar_t** argv, Args& a) {
  std::vector<std::wstring> raw(argv + 1, argv + argc), v;
  if (!ExpandParams(raw, v)) return false;
  for (size_t i = 0; i < v.size(); ++i) {
    const std::wstring& f = v[i];
    if (f == L"--") {
      a.cmd.assign(v.begin() + i + 1, v.end());
      if (a.cmd.empty()) { Err(L"no command after --"); return false; }
      return true;
    }
    if (f == L"-h" || f == L"--help") {
      wprintf(L"BazelSandbox (PSEC, native) 0.1\n%s\n", kUsage);
      exit(0);
    }
    if (f == L"-D") { a.debug = true; continue; }
    if (i + 1 >= v.size()) { Err(L"missing value for %s", f.c_str()); return false; }
    const std::wstring& val = v[++i];
    if (f == L"-W") a.cwd = val;
    else if (f == L"-T") a.timeoutMs = (DWORD)(_wtoi(val.c_str()) * 1000);
    else if (f == L"-t") {}  // kill delay: not modelled
    else if (f == L"-l") a.stdoutPath = val;
    else if (f == L"-L") a.stderrPath = val;
    else if (f == L"-w") a.rw.push_back(val);
    else if (f == L"-r") a.ro.push_back(val);
    else if (f == L"-b") a.deny.push_back(val);
    else { Err(L"unknown flag %s\n%s", f.c_str(), kUsage); return false; }
  }
  Err(L"no command after --");
  return false;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

struct Policy {
  std::vector<std::wstring> rw, ro, deny, enumerate;
};

void AddTargets(std::vector<std::wstring>& v) {
  std::vector<std::wstring> extra;
  for (const auto& p : v) {
    std::wstring t = FinalPath(p);
    if (!t.empty() && Key(t) != Key(p)) extra.push_back(t);
  }
  v.insert(v.end(), extra.begin(), extra.end());
}

Policy BuildPolicy(const Args& a, const std::wstring& cwd, const std::vector<std::wstring>& extraRo,
                   const std::vector<std::wstring>& extraRw, bool dirGrants, bool enumerate, bool widen) {
  Policy pol;
  // Declared outputs do not exist yet and the kernel policy cannot grant a
  // missing file, so widen those grants to the parent directory.
  for (const auto& p : a.rw) {
    if (!widen || Exists(p)) pol.rw.push_back(p);
    else { std::wstring d = Parent(p); pol.rw.push_back(d.empty() ? p : d); }
  }
  pol.rw.insert(pol.rw.end(), extraRw.begin(), extraRw.end());
  // Runfiles directories (<tool>.runfiles, an output of Bazel's own) are the
  // cwd of every test. The kernel policy denies FILE_TRAVERSE opens, i.e.
  // SetCurrentDirectory, under a read-only grant (see
  // GAPS-all-actions-sandboxed.md), so grant them read-write instead unless
  // BAZEL_PSEC_RUNFILES_RO is set.
  const bool runfilesRw = !EnvSet(L"BAZEL_PSEC_RUNFILES_RO");
  for (const auto& p : a.ro) {
    std::wstring k = Key(p);
    if (runfilesRw && k.size() > 9 && k.compare(k.size() - 9, 9, L".runfiles") == 0 && IsDir(p)) pol.rw.push_back(p);
    else pol.ro.push_back(p);
  }
  pol.ro.insert(pol.ro.end(), extraRo.begin(), extraRo.end());
  // The execroot is a symlink forest and the policy is evaluated on the
  // resolved target, so grant that too.
  AddTargets(pol.ro);
  AddTargets(pol.rw);
  // Most restrictive intent wins for a path listed twice (or under a weaker
  // ancestor): a read-only grant must never equal or contain a read-write one.
  std::vector<std::wstring> rwKeys;
  for (const auto& p : pol.rw) rwKeys.push_back(Key(p));
  auto containsRw = [&](const std::wstring& d) {
    std::wstring dk = Key(d);
    for (const auto& r : rwKeys) if (Under(r, dk)) return true;
    return false;
  };
  if (dirGrants) {
    for (auto& p : pol.ro) {
      if (IsFile(p)) {
        std::wstring d = Parent(p);
        if (!d.empty() && !containsRw(d)) p = d;
      }
    }
  }
  std::vector<std::wstring> ro2;
  for (const auto& p : pol.ro) if (!containsRw(p)) ro2.push_back(p);
  pol.ro.swap(ro2);
  Dedupe(pol.ro); Dedupe(pol.rw);
  PruneNested(pol.ro); PruneNested(pol.rw);
  pol.deny = a.deny;
  // Enumerate-only ancestors (PSEC 1.1): for every grant and the cwd, walk the
  // ancestor chain top-down and list the ancestors above the first grant.
  // Never enumerate a path a grant covers: that would downgrade the grant.
  if (enumerate) {
    std::unordered_set<std::wstring> grantKeys, seen;
    for (const auto& p : pol.ro) grantKeys.insert(Key(p));
    for (const auto& p : pol.rw) grantKeys.insert(Key(p));
    auto walk = [&](const std::wstring& start) {
      std::vector<std::wstring> chain;
      for (std::wstring d = start; !d.empty(); d = Parent(d)) chain.push_back(d);
      bool covered = false;
      for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        std::wstring k = Key(*it);
        if (grantKeys.count(k)) covered = true;
        if (!covered && seen.insert(k).second) pol.enumerate.push_back(*it);
      }
    };
    for (const auto& p : pol.ro) walk(Parent(p));
    for (const auto& p : pol.rw) walk(Parent(p));
    walk(cwd);
  }
  return pol;
}

// ---------------------------------------------------------------------------
// Environment block
// ---------------------------------------------------------------------------

struct EnvVar { std::wstring name, value; };

std::vector<EnvVar> CurrentEnv() {
  std::vector<EnvVar> out;
  wchar_t* block = GetEnvironmentStringsW();
  for (wchar_t* p = block; *p;) {
    std::wstring entry = p;
    p += entry.size() + 1;
    size_t eq = entry.find(L'=', 1);
    if (entry.empty() || entry[0] == L'=' || eq == std::wstring::npos) continue;
    out.push_back({entry.substr(0, eq), entry.substr(eq + 1)});
  }
  FreeEnvironmentStringsW(block);
  return out;
}

EnvVar* Find(std::vector<EnvVar>& env, const wchar_t* name) {
  for (auto& e : env) if (_wcsicmp(e.name.c_str(), name) == 0) return &e;
  return nullptr;
}

void SetVar(std::vector<EnvVar>& env, const wchar_t* name, const std::wstring& value) {
  if (EnvVar* e = Find(env, name)) e->value = value;
  else env.push_back({name, value});
}

std::vector<wchar_t> EnvBlock(const std::vector<EnvVar>& env) {
  std::vector<wchar_t> block;
  for (const auto& e : env) {
    block.insert(block.end(), e.name.begin(), e.name.end());
    block.push_back(L'=');
    block.insert(block.end(), e.value.begin(), e.value.end());
    block.push_back(L'\0');
  }
  block.push_back(L'\0');
  return block;
}

std::wstring ProfileDir() {
  if (auto v = GetEnv(L"USERPROFILE")) return *v;
  HANDLE tok = nullptr;
  std::wstring dir;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
    wchar_t buf[MAX_PATH]; DWORD n = MAX_PATH;
    if (GetUserProfileDirectoryW(tok, buf, &n)) dir = buf;
    CloseHandle(tok);
  }
  return dir;
}

}  // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int wmain(int argc, wchar_t** argv) {
  auto t0 = Clock::now();
  Args args;
  if (!ParseArgs(argc, argv, args)) return 64;

  const bool debug = args.debug || EnvSet(L"BAZEL_MXC_DEBUG");
  const bool dirGrants = EnvSet(L"BAZEL_MXC_DIR_GRANTS");
  const bool enumerate = !EnvSet(L"BAZEL_MXC_NO_ENUM");
  const bool ui = !EnvSet(L"BAZEL_MXC_NO_UI");
  const bool noSandbox = EnvSet(L"BAZEL_PSEC_NO_SANDBOX");
  const bool widen = !EnvSet(L"BAZEL_PSEC_NO_WIDEN");
  const std::wstring logFile = GetEnv(L"BAZEL_PSEC_LOG").value_or(L"");

  // Bazel never passes -W: it starts us with cwd = execroot.
  std::wstring cwd = args.cwd;
  if (cwd.empty()) {
    wchar_t buf[32768]; DWORD n = GetCurrentDirectoryW(32768, buf);
    cwd.assign(buf, n);
  }

  std::vector<std::wstring> extraRo, extraRw;
  if (auto v = GetEnv(L"BAZEL_MXC_EXTRA_RO")) extraRo = SplitSemi(*v);
  if (auto v = GetEnv(L"BAZEL_PSEC_EXTRA_RW")) extraRw = SplitSemi(*v);

  // Environment: ours, verbatim (Bazel already scrubbed it), plus what PSEC
  // insists on and the temp-directory arrangements.
  std::vector<EnvVar> env = CurrentEnv();
  std::wstring profile = ProfileDir();
  if (!Find(env, L"USERPROFILE")) SetVar(env, L"USERPROFILE", profile);
  if (!Find(env, L"LOCALAPPDATA")) SetVar(env, L"LOCALAPPDATA", profile + L"\\AppData\\Local");
  std::wstring shortTmp;
  if (auto root = GetEnv(L"BAZEL_PSEC_SHORT_TMP")) {
    CreateDirectoryW(root->c_str(), nullptr);
    shortTmp = *root + L"\\" + std::to_wstring(GetCurrentProcessId());
    if (CreateDirectoryW(shortTmp.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS) {
      SetVar(env, L"TMP", shortTmp);
      SetVar(env, L"TEMP", shortTmp);
      SetVar(env, L"TMPDIR", shortTmp);
      extraRw.push_back(shortTmp);
    } else {
      Err(L"cannot create %s: %u", shortTmp.c_str(), GetLastError());
      shortTmp.clear();
    }
  }
  // Windows rewrites TEMP/TMP/LOCALAPPDATA inside the environment to the
  // per-container AC\Temp; TMPDIR survives and Python's tempfile prefers it.
  if (!EnvSet(L"BAZEL_PSEC_NO_TMPDIR") && !Find(env, L"TMPDIR")) {
    if (EnvVar* tmp = Find(env, L"TMP")) SetVar(env, L"TMPDIR", tmp->value);
  }

  Policy pol = BuildPolicy(args, cwd, extraRo, extraRw, dirGrants, enumerate, widen);

  // argv[0]: Bazel hands it over as it appears in the action, possibly
  // relative with forward slashes; cmd.exe would parse the `/` as switches.
  std::vector<std::wstring> argvv = args.cmd;
  if (argvv[0].find_first_of(L"\\/") != std::wstring::npos) {
    std::wstring abs = IsAbsolute(argvv[0]) ? argvv[0] : cwd + L"\\" + argvv[0];
    if (Exists(abs)) argvv[0] = Backslashes(abs);
  }
  // Bazel's own Windows subprocess factory appends the arguments of cmd.exe
  // verbatim (cmd.exe does not use the CRT's quoting rules; a cmd_bat genrule
  // passes its whole command, embedded quotes included, as one argument).
  // Everything else is quoted the CRT way, like ShellUtils.windowsEscapeArg.
  std::wstring cmdline;
  std::wstring argv0Lower = Key(argvv[0]);
  bool isCmd = argv0Lower == L"cmd.exe" || (argv0Lower.size() > 8 && argv0Lower.compare(argv0Lower.size() - 8, 8, L"\\cmd.exe") == 0);
  for (size_t i = 0; i < argvv.size(); ++i) {
    if (i) cmdline += L' ';
    if (isCmd && i > 0) cmdline += argvv[i];
    else QuoteArg(cmdline, argvv[i]);
  }

  // A grant longer than MAX_PATH only takes effect when it carries the \\?\
  // prefix (processmodel.dll does not resolve plain long paths; see
  // GAPS-all-actions-sandboxed.md, gap 13). Short paths are passed plain.
  auto specPath = [](const std::wstring& p) {
    return ToUtf8(p.size() >= 248 ? LongPath(p) : p);
  };
  Spec spec;
  for (const auto& p : pol.rw) spec.read_write.push_back(specPath(p));
  for (const auto& p : pol.ro) spec.read_only.push_back(specPath(p));
  for (const auto& p : pol.deny) spec.deny.push_back(specPath(p));
  for (const auto& p : pol.enumerate) spec.enumerate.push_back(specPath(p));
  spec.disallow_win32k = !ui;
  if (auto m = GetEnv(L"BAZEL_PSEC_UI_MASK")) spec.ui_restrictions = wcstoull(m->c_str(), nullptr, 16);
  spec.allow_network = EnvSet(L"BAZEL_PSEC_NET");
  if (spec.allow_network) spec.capabilities = "internetClient";
  if (auto c = GetEnv(L"BAZEL_PSEC_CAPS")) {
    if (!spec.capabilities.empty()) spec.capabilities += ",";
    spec.capabilities += ToUtf8(*c);
  }

  std::string logText;
  if (debug || !logFile.empty()) {
    std::string s = "BazelSandbox: cwd=" + ToUtf8(cwd) + "\n  command=" + ToUtf8(cmdline) + "\n";
    for (const auto& p : pol.rw) s += "  rw " + ToUtf8(p) + "\n";
    for (const auto& p : pol.ro) s += "  ro " + ToUtf8(p) + "\n";
    for (const auto& p : pol.deny) s += "  deny " + ToUtf8(p) + "\n";
    for (const auto& p : pol.enumerate) s += "  enum " + ToUtf8(p) + "\n";
    char b[160];
    snprintf(b, sizeof b, "  ui_restrictions=0x%llX win32k_lockdown=%d net=%d caps=%s sandbox=%d\n",
             (unsigned long long)spec.ui_restrictions, spec.disallow_win32k, spec.allow_network,
             spec.capabilities.c_str(), !noSandbox);
    s += b;
    if (debug) { fputs(s.c_str(), stderr); fflush(stderr); }
    logText = s;
  }

  // Phase 1: the security environment.
  Api api;
  HANDLE envHandle = nullptr;
  if (!noSandbox) {
    api = LoadApi();
    if (!api.create) { Err(L"%s", api.error.c_str()); return 1; }
    std::vector<uint8_t> blob = EncodeSpec(spec, 1, api.minor, (api.support & 0x8) && !EnvSet(L"BAZEL_PSEC_NO_INGRESS"));
    HRESULT hr = api.create(blob.data(), (DWORD)blob.size(), 0, &envHandle);
    if (FAILED(hr) || !envHandle) {
      Err(L"CreateProcessSecurityEnvironment failed: hr=0x%08X (%zu ro, %zu rw, %zu enum, %zu deny paths)",
          (unsigned)hr, pol.ro.size(), pol.rw.size(), pol.enumerate.size(), pol.deny.size());
      if (!logFile.empty()) AppendFile(logFile, logText + "  RESULT create failed\n");
      return 1;
    }
  }
  auto tPrep = MsSince(t0);

  // Phase 2: attach and launch. Stdio is inherited (or redirected to -l/-L).
  HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE), hOut = GetStdHandle(STD_OUTPUT_HANDLE), hErr = GetStdHandle(STD_ERROR_HANDLE);
  SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
  HANDLE fOut = INVALID_HANDLE_VALUE, fErr = INVALID_HANDLE_VALUE;
  if (!args.stdoutPath.empty()) {
    fOut = CreateFileW(args.stdoutPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fOut != INVALID_HANDLE_VALUE) hOut = fOut; else Err(L"cannot create %s: %u", args.stdoutPath.c_str(), GetLastError());
  }
  if (!args.stderrPath.empty()) {
    fErr = CreateFileW(args.stderrPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fErr != INVALID_HANDLE_VALUE) hErr = fErr; else Err(L"cannot create %s: %u", args.stderrPath.c_str(), GetLastError());
  }
  std::vector<HANDLE> inherit;
  for (HANDLE h : {hIn, hOut, hErr}) {
    if (h && h != INVALID_HANDLE_VALUE && std::find(inherit.begin(), inherit.end(), h) == inherit.end()) {
      SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
      inherit.push_back(h);
    }
  }
  DWORD mode;
  bool console = GetConsoleMode(hOut, &mode) != 0;

  SIZE_T sz = 0;
  InitializeProcThreadAttributeList(nullptr, 2, 0, &sz);
  std::vector<uint8_t> albuf(sz);
  auto al = (LPPROC_THREAD_ATTRIBUTE_LIST)albuf.data();
  if (!InitializeProcThreadAttributeList(al, 2, 0, &sz)) { Err(L"InitializeProcThreadAttributeList: %u", GetLastError()); return 1; }
  if (envHandle && !UpdateProcThreadAttribute(al, 0, kProcThreadAttributeSecurityEnvironment, &envHandle, sizeof(envHandle), nullptr, nullptr)) {
    Err(L"UpdateProcThreadAttribute(security environment): %u", GetLastError()); return 1;
  }
  if (!inherit.empty() && !UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit.data(), inherit.size() * sizeof(HANDLE), nullptr, nullptr)) {
    Err(L"UpdateProcThreadAttribute(handle list): %u", GetLastError()); return 1;
  }
  STARTUPINFOEXW si{};
  si.StartupInfo.cb = sizeof(si);
  si.lpAttributeList = al;
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  si.StartupInfo.hStdInput = hIn; si.StartupInfo.hStdOutput = hOut; si.StartupInfo.hStdError = hErr;

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (!job) { Err(L"CreateJobObject: %u", GetLastError()); return 1; }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
  jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));

  std::vector<wchar_t> block = EnvBlock(env);
  std::vector<wchar_t> cl(cmdline.begin(), cmdline.end()); cl.push_back(0);
  PROCESS_INFORMATION pi{};
  DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | (console ? 0 : CREATE_NO_WINDOW);
  BOOL ok = CreateProcessW(nullptr, cl.data(), nullptr, nullptr, TRUE, flags, block.data(), cwd.c_str(), &si.StartupInfo, &pi);
  DWORD createErr = ok ? 0 : GetLastError();
  if (!ok) {
    Err(L"CreateProcessW failed: %u (%s)", createErr, cmdline.c_str());
    if (createErr == ERROR_ACCESS_DENIED) Err(L"  (is the executable covered by a read-only grant and its directory enumerable?)");
    if (!logFile.empty()) { char b[64]; snprintf(b, sizeof b, "  RESULT CreateProcessW error %u\n", createErr); AppendFile(logFile, logText + b); }
    if (envHandle) api.close(envHandle);
    if (!shortTmp.empty()) RemoveTree(shortTmp);
    return 1;
  }
  if (!AssignProcessToJobObject(job, pi.hProcess)) {
    Err(L"AssignProcessToJobObject: %u; terminating", GetLastError());
    TerminateProcess(pi.hProcess, 1);
    return 1;
  }
  ResumeThread(pi.hThread);
  auto tSpawn = MsSince(t0);
  DWORD wait = WaitForSingleObject(pi.hProcess, args.timeoutMs ? *args.timeoutMs : INFINITE);
  DWORD code = 1;
  if (wait == WAIT_TIMEOUT) {
    Err(L"action timed out after %u s", *args.timeoutMs / 1000);
    TerminateJobObject(job, 124);
    WaitForSingleObject(pi.hProcess, 5000);
    code = 124;
  } else {
    GetExitCodeProcess(pi.hProcess, &code);
    if (code == 0xC0000142) Err(L"child died with STATUS_DLL_INIT_FAILED: USER32 importers cannot start in a security environment from session 0 (ssh/service); run from an interactive session");
  }
  auto tTotal = MsSince(t0);
  CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
  CloseHandle(job);  // kills stragglers in the tree
  DeleteProcThreadAttributeList(al);
  if (envHandle) api.close(envHandle);
  if (fOut != INVALID_HANDLE_VALUE) CloseHandle(fOut);
  if (fErr != INVALID_HANDLE_VALUE) CloseHandle(fErr);
  if (!shortTmp.empty()) RemoveTree(shortTmp);

  if (!logFile.empty()) {
    // One line per successful action, the whole policy for a failed one.
    char b[64]; snprintf(b, sizeof b, "  RESULT exit %u (0x%X)\n", code, code);
    if (code == 0 && !EnvSet(L"BAZEL_PSEC_LOG_ALL")) AppendFile(logFile, "OK " + ToUtf8(cmdline).substr(0, 300) + "\n");
    else AppendFile(logFile, logText + b);
  }
  if (auto t = GetEnv(L"BAZEL_MXC_TIMING")) {
    char b[200];
    snprintf(b, sizeof b, "%.0f\t%.0f\t%.0f\t%.0f\t%zu\t%zu\t%zu\t%u\n", tPrep, tSpawn - tPrep, tTotal - tSpawn, tTotal,
             pol.ro.size(), pol.rw.size(), pol.enumerate.size(), code);
    AppendFile(*t, b);
  }
  return (int)code;
}
