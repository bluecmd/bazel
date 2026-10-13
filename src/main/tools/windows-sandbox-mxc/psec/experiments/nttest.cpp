// nttest.exe: probes to run INSIDE a security environment (no USER32 import, so it also runs from session 0).
//   token                      integrity level, AppContainer-ness, package SID, capabilities, privileges
//   pipe <name>                CreateNamedPipeW(\\.\pipe\<name>)
//   event <name>               CreateEventW(<name>) (Global\ or plain)
//   chdir <dir>                SetCurrentDirectoryW
//   open <path> r|w|rw|x|d     CreateFileW with GENERIC_READ / WRITE / both / EXECUTE / FILE_LIST_DIRECTORY (backup semantics)
//   symlink <link> <target> f|d   CreateSymbolicLinkW (with the unprivileged-create flag)
//   junction <link> <target>   mkdir + FSCTL_SET_REPARSE_POINT (mount point)
//   hardlink <link> <target>   CreateHardLinkW
//   mkdir <dir>                CreateDirectoryW
//   section <name>             CreateFileMappingW named (pagefile-backed)
//   exec <cmdline>             CreateProcessW and wait
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <sddl.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")
#include <cstdio>
#include <string>
#include <vector>
#pragma comment(lib, "advapi32.lib")
struct MY_REPARSE { ULONG ReparseTag; USHORT ReparseDataLength; USHORT Reserved; USHORT SubstituteNameOffset; USHORT SubstituteNameLength; USHORT PrintNameOffset; USHORT PrintNameLength; WCHAR PathBuffer[1]; };
static void R(const wchar_t* what, BOOL ok) { DWORD e = GetLastError(); wprintf(L"%s: %ls (GetLastError=%u)\n", what, ok ? L"OK" : L"FAIL", ok ? 0 : e); }
int wmain(int argc, wchar_t** argv) {
  if (argc < 2) return 2;
  std::wstring m = argv[1];
  if (m == L"token") {
    HANDLE t; OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t);
    DWORD isac = 0, n = 0; GetTokenInformation(t, TokenIsAppContainer, &isac, sizeof isac, &n);
    wprintf(L"TokenIsAppContainer=%u\n", isac);
    BYTE buf[4096]; LPWSTR s;
    if (GetTokenInformation(t, TokenIntegrityLevel, buf, sizeof buf, &n)) { auto* tml = (TOKEN_MANDATORY_LABEL*)buf; ConvertSidToStringSidW(tml->Label.Sid, &s); wprintf(L"IntegrityLevel=%ls\n", s); }
    if (GetTokenInformation(t, TokenAppContainerSid, buf, sizeof buf, &n)) { auto* ta = (TOKEN_APPCONTAINER_INFORMATION*)buf; if (ta->TokenAppContainer) { ConvertSidToStringSidW(ta->TokenAppContainer, &s); wprintf(L"AppContainerSid=%ls\n", s); } else wprintf(L"AppContainerSid=(none)\n"); }
    if (GetTokenInformation(t, TokenCapabilities, buf, sizeof buf, &n)) { auto* tg = (TOKEN_GROUPS*)buf; wprintf(L"Capabilities=%u\n", tg->GroupCount); for (DWORD i = 0; i < tg->GroupCount; i++) { ConvertSidToStringSidW(tg->Groups[i].Sid, &s); wprintf(L"  %ls\n", s); } }
    if (GetTokenInformation(t, TokenGroups, buf, sizeof buf, &n)) { auto* tg = (TOKEN_GROUPS*)buf; wprintf(L"Groups=%u\n", tg->GroupCount); for (DWORD i = 0; i < tg->GroupCount; i++) { ConvertSidToStringSidW(tg->Groups[i].Sid, &s); wprintf(L"  %ls attr=0x%X\n", s, tg->Groups[i].Attributes); } }
    DWORD sess = 0; GetTokenInformation(t, TokenSessionId, &sess, sizeof sess, &n); wprintf(L"SessionId=%u\n", sess);
    if (GetTokenInformation(t, TokenPrivileges, buf, sizeof buf, &n)) { auto* tp = (TOKEN_PRIVILEGES*)buf; wprintf(L"Privileges=%u\n", tp->PrivilegeCount); for (DWORD i = 0; i < tp->PrivilegeCount; i++) { wchar_t nm[128]; DWORD l = 128; LookupPrivilegeNameW(nullptr, &tp->Privileges[i].Luid, nm, &l); wprintf(L"  %ls attr=0x%X\n", nm, tp->Privileges[i].Attributes); } }
    DWORD elev = 0; GetTokenInformation(t, TokenElevationType, &elev, sizeof elev, &n); wprintf(L"ElevationType=%u\n", elev);
    return 0;
  }
  if (m == L"derivesid") {
    // DeriveAppContainerSidFromAppContainerName is in userenv (public)
    HMODULE ue = LoadLibraryW(L"userenv.dll");
    if (!ue) { wprintf(L"no userenv\n"); return 1; }
    typedef long(__stdcall* DeriveFn)(LPCWSTR, PSID*);
    DeriveFn derive = (DeriveFn)GetProcAddress(ue, "DeriveAppContainerSidFromAppContainerName");
    if (!derive) { wprintf(L"no export\n"); return 1; }
    PSID sid = nullptr;
    long hr = derive(argv[2], &sid);
    if (hr < 0) { wprintf(L"derive hr=0x%08X\n", (unsigned)hr); return 1; }
    LPWSTR s;
    ConvertSidToStringSidW(sid, &s); wprintf(L"DerivedSid=%ls\n", s); LocalFree(s);
    FreeLibrary(ue);
    return 0;
  }
  if (m == L"actoken") {
    // Isolate CreateAppContainerToken: derive the SID for the profile name in
    // argv[2], then create an AppContainer token from our process token.
    // kernelbase!CreateAppContainerToken(token, struct{PSID sid; void* caps;
    // DWORD count; DWORD pad;}, PHANDLE out) - it feeds NtCreateLowBoxToken.
    HMODULE ue = LoadLibraryW(L"userenv.dll");
    typedef long(__stdcall* DeriveFn2)(LPCWSTR, PSID*);
    DeriveFn2 derive = (DeriveFn2)GetProcAddress(ue, "DeriveAppContainerSidFromAppContainerName");
    PSID sid = nullptr;
    long hr = derive(argv[2], &sid);
    wprintf(L"derive hr=0x%08X\n", (unsigned)hr);
    if (hr < 0) return 1;
    LPWSTR s; ConvertSidToStringSidW(sid, &s); wprintf(L"sid=%ls\n", s); LocalFree(s);
    HMODULE kb = GetModuleHandleW(L"kernelbase.dll");
    typedef BOOL(WINAPI* CatFn)(HANDLE, void*, PHANDLE);
    CatFn cat = (CatFn)GetProcAddress(kb, "CreateAppContainerToken");
    wprintf(L"cat=%p\n", (void*)cat);
    if (!cat) return 1;
    struct { PSID sid; void* caps; DWORD count; DWORD pad; } sac { sid, nullptr, 0, 0 };
    HANDLE tok = nullptr, self = nullptr;
    OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &self);
    wprintf(L"calling\n"); fflush(stdout);
    BOOL ok = cat(self, &sac, &tok);
    DWORD e = GetLastError();
    wprintf(L"CreateAppContainerToken ok=%u err=%u tok=%p\n", ok, e, (void*)tok);
    if (tok) {
      if (argc > 3 && !wcscmp(argv[3], L"tokdump")) {
        for (DWORD cls = 20; cls < 56; ++cls) {
          DWORD buf[16] = {}; DWORD ret = 0;
          if (GetTokenInformation(tok, (TOKEN_INFORMATION_CLASS)cls, buf, sizeof buf, &ret))
            wprintf(L"cls=%u d0=%u d1=%u ret=%u\n", cls, buf[0], buf[1], ret);
        }
      }
      CloseHandle(tok);
    }
    return ok ? 0 : 1;
  }
  if (m == L"tokdump") {
    HANDLE t; OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t);
    for (DWORD cls = 20; cls < 56; ++cls) {
      DWORD buf[16] = {}; DWORD ret = 0;
      if (GetTokenInformation(t, (TOKEN_INFORMATION_CLASS)cls, buf, sizeof buf, &ret))
        wprintf(L"cls=%u d0=%u d1=%u ret=%u\n", cls, buf[0], buf[1], ret);
    }
    return 0;
  }
  if (m == L"pipe") { std::wstring nm = std::wstring(L"\\\\.\\pipe\\") + argv[2]; HANDLE h = CreateNamedPipeW(nm.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 4096, 4096, 0, nullptr); R(nm.c_str(), h != INVALID_HANDLE_VALUE); return 0; }
  if (m == L"event") { HANDLE h = CreateEventW(nullptr, TRUE, FALSE, argv[2]); R(argv[2], h != nullptr); return 0; }
  if (m == L"section") { HANDLE h = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 4096, argv[2]); R(argv[2], h != nullptr); return 0; }
  if (m == L"chdir") { R(argv[2], SetCurrentDirectoryW(argv[2])); wchar_t b[1024]; GetCurrentDirectoryW(1024, b); wprintf(L"  cwd now %ls\n", b); return 0; }
  if (m == L"open") {
    std::wstring mode = argv[3]; DWORD acc = 0, flags = FILE_ATTRIBUTE_NORMAL;
    if (mode == L"r") acc = GENERIC_READ; else if (mode == L"w") acc = GENERIC_WRITE; else if (mode == L"rw") acc = GENERIC_READ | GENERIC_WRITE; else if (mode == L"x") acc = GENERIC_EXECUTE | GENERIC_READ; else if (mode == L"d") { acc = FILE_LIST_DIRECTORY; flags = FILE_FLAG_BACKUP_SEMANTICS; } else if (mode == L"t") { acc = FILE_TRAVERSE; flags = FILE_FLAG_BACKUP_SEMANTICS; } else if (mode == L"a") { acc = FILE_READ_ATTRIBUTES; flags = FILE_FLAG_BACKUP_SEMANTICS; }
    HANDLE h = CreateFileW(argv[2], acc, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, flags, nullptr);
    R((std::wstring(argv[2]) + L" [" + mode + L"]").c_str(), h != INVALID_HANDLE_VALUE); return 0;
  }
  if (m == L"symlink") { DWORD f = (argc > 4 && argv[4][0] == L'd') ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0; R(L"CreateSymbolicLinkW", CreateSymbolicLinkW(argv[2], argv[3], f | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)); return 0; }
  if (m == L"hardlink") { R(L"CreateHardLinkW", CreateHardLinkW(argv[2], argv[3], nullptr)); return 0; }
  if (m == L"mkdir") { R(argv[2], CreateDirectoryW(argv[2], nullptr)); return 0; }
  if (m == L"junction") {
    R(L"CreateDirectoryW", CreateDirectoryW(argv[2], nullptr));
    HANDLE h = CreateFileW(argv[2], GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    R(L"open link dir for write", h != INVALID_HANDLE_VALUE); if (h == INVALID_HANDLE_VALUE) return 1;
    std::wstring target = std::wstring(L"\\??\\") + argv[3]; std::wstring print = argv[3];
    std::vector<BYTE> rb(sizeof(MY_REPARSE) + (target.size() + print.size() + 2) * 2 + 16);
    auto* rd = (MY_REPARSE*)rb.data(); rd->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    rd->SubstituteNameOffset = 0; rd->SubstituteNameLength = (USHORT)(target.size() * 2);
    rd->PrintNameOffset = (USHORT)(target.size() * 2 + 2); rd->PrintNameLength = (USHORT)(print.size() * 2);
    memcpy(rd->PathBuffer, target.c_str(), target.size() * 2 + 2);
    memcpy((BYTE*)rd->PathBuffer + target.size() * 2 + 2, print.c_str(), print.size() * 2 + 2);
    rd->ReparseDataLength = (USHORT)(8 + target.size() * 2 + 2 + print.size() * 2 + 2);
    DWORD ret = 0; R(L"FSCTL_SET_REPARSE_POINT", DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, rd, rd->ReparseDataLength + 8, nullptr, 0, &ret, nullptr));
    CloseHandle(h); return 0;
  }
  if (m == L"ntopen") {  // ntopen <path> <access-hex> <options-hex>
    std::wstring nt = std::wstring(L"\\??\\") + argv[2]; UNICODE_STRING us; RtlInitUnicodeString(&us, nt.c_str());
    OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr); IO_STATUS_BLOCK io{}; HANDLE h = nullptr;
    NTSTATUS st = NtOpenFile(&h, (ACCESS_MASK)wcstoul(argv[3], nullptr, 16), &oa, &io, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, (ULONG)wcstoul(argv[4], nullptr, 16));
    wprintf(L"NtOpenFile(%s, access=0x%s, options=0x%ls) = 0x%08X\n", argv[2], argv[3], argv[4], (unsigned)st); if (h) CloseHandle(h); return 0;
  }
  if (m == L"mitig") {
    PROCESS_MITIGATION_ASLR_POLICY a{}; GetProcessMitigationPolicy(GetCurrentProcess(), ProcessASLRPolicy, &a, sizeof a);
    wprintf(L"ASLR: EnableBottomUp=%u EnableForceRelocateImages=%u EnableHighEntropy=%u DisallowStrippedImages=%u\n", a.EnableBottomUpRandomization, a.EnableForceRelocateImages, a.EnableHighEntropy, a.DisallowStrippedImages);
    PROCESS_MITIGATION_DEP_POLICY d{}; GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDEPPolicy, &d, sizeof d); wprintf(L"DEP: Enable=%u Permanent=%u\n", d.Enable, d.Permanent);
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dc{}; GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &dc, sizeof dc); wprintf(L"DynamicCode: Prohibit=%u\n", dc.ProhibitDynamicCode);
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY bs{}; GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy, &bs, sizeof bs); wprintf(L"Signature: MicrosoftSignedOnly=%u StoreSignedOnly=%u\n", bs.MicrosoftSignedOnly, bs.StoreSignedOnly);
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY il{}; GetProcessMitigationPolicy(GetCurrentProcess(), ProcessImageLoadPolicy, &il, sizeof il); wprintf(L"ImageLoad: NoRemoteImages=%u NoLowMandatoryLabelImages=%u PreferSystem32=%u\n", il.NoRemoteImages, il.NoLowMandatoryLabelImages, il.PreferSystem32Images);
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY sc{}; GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSystemCallDisablePolicy, &sc, sizeof sc); wprintf(L"Win32k: DisallowWin32kSystemCalls=%u\n", sc.DisallowWin32kSystemCalls);
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cf{}; GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &cf, sizeof cf); wprintf(L"CFG: Enable=%u StrictMode=%u\n", cf.EnableControlFlowGuard, cf.StrictMode);
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY cp{}; GetProcessMitigationPolicy(GetCurrentProcess(), ProcessChildProcessPolicy, &cp, sizeof cp); wprintf(L"ChildProcess: NoChildProcessCreation=%u\n", cp.NoChildProcessCreation);
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ep{}; GetProcessMitigationPolicy(GetCurrentProcess(), ProcessExtensionPointDisablePolicy, &ep, sizeof ep); wprintf(L"ExtensionPoints: Disable=%u\n", ep.DisableExtensionPoints);
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY sh{}; GetProcessMitigationPolicy(GetCurrentProcess(), ProcessStrictHandleCheckPolicy, &sh, sizeof sh); wprintf(L"StrictHandle: RaiseOnInvalid=%u\n", sh.RaiseExceptionOnInvalidHandleReference);
    return 0;
  }
  if (m == L"sleep") { Sleep(_wtoi(argv[2])); wprintf(L"slept %ls ms\n", argv[2]); return 0; }
  if (m == L"mkfiles") {  // mkfiles <base> <n>: n small files in <base>\dNNN\fNNNNN.txt
    std::wstring base = argv[2]; int n = _wtoi(argv[3]); CreateDirectoryW(base.c_str(), nullptr);
    for (int i = 0; i < n; i++) {
      wchar_t d[1024], f[1024]; swprintf(d, 1024, L"%ls\\d%03d", base.c_str(), i / 256); if (i % 256 == 0) CreateDirectoryW(d, nullptr);
      swprintf(f, 1024, L"%ls\\f%05d.txt", d, i);
      HANDLE h = CreateFileW(f, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr); DWORD w; WriteFile(h, "x", 1, &w, nullptr); CloseHandle(h);
    }
    wprintf(L"created %d files under %ls\n", n, base.c_str()); return 0;
  }
  if (m == L"listfiles") {  // listfiles <base> <n> : print the file paths (for a params file)
    std::wstring base = argv[2]; int n = _wtoi(argv[3]);
    for (int i = 0; i < n; i++) wprintf(L"-r\n%ls\\d%03d\\f%05d.txt\n", base.c_str(), i / 256, i);
    return 0;
  }
  if (m == L"openloop") {  // openloop <base> <n> <iters>: open+read+close every file, iters times; prints ms
    std::wstring base = argv[2]; int n = _wtoi(argv[3]); int iters = _wtoi(argv[4]);
    LARGE_INTEGER f0, t0, t1; QueryPerformanceFrequency(&f0); QueryPerformanceCounter(&t0); int fails = 0;
    for (int it = 0; it < iters; it++) for (int i = 0; i < n; i++) {
      wchar_t f[1024]; swprintf(f, 1024, L"%ls\\d%03d\\f%05d.txt", base.c_str(), i / 256, i);
      HANDLE h = CreateFileW(f, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (h == INVALID_HANDLE_VALUE) { fails++; continue; }
      char b[4]; DWORD r; ReadFile(h, b, 1, &r, nullptr); CloseHandle(h);
    }
    QueryPerformanceCounter(&t1);
    wprintf(L"openloop n=%d iters=%d fails=%d %.1f ms (%.1f us/open)\n", n, iters, fails, (t1.QuadPart - t0.QuadPart) * 1000.0 / f0.QuadPart, (t1.QuadPart - t0.QuadPart) * 1e6 / f0.QuadPart / (double)(n * iters));
    return 0;
  }
  if (m == L"exec") { std::wstring cl; for (int i = 2; i < argc; i++) { if (i > 2) cl += L' '; cl += argv[i]; } STARTUPINFOW si{sizeof si}; PROCESS_INFORMATION pi{}; BOOL ok = CreateProcessW(nullptr, &cl[0], nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi); R(cl.c_str(), ok); if (ok) { WaitForSingleObject(pi.hProcess, INFINITE); DWORD c; GetExitCodeProcess(pi.hProcess, &c); wprintf(L"  exit %u (0x%X)\n", c, c); } return 0; }
  wprintf(L"unknown mode\n"); return 2;
}
