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
static void R(const wchar_t* what, BOOL ok) { DWORD e = GetLastError(); wprintf(L"%s: %s (GetLastError=%u)\n", what, ok ? L"OK" : L"FAIL", ok ? 0 : e); }
int wmain(int argc, wchar_t** argv) {
  if (argc < 2) return 2;
  std::wstring m = argv[1];
  if (m == L"token") {
    HANDLE t; OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t);
    DWORD isac = 0, n = 0; GetTokenInformation(t, TokenIsAppContainer, &isac, sizeof isac, &n);
    wprintf(L"TokenIsAppContainer=%u\n", isac);
    BYTE buf[4096]; LPWSTR s;
    if (GetTokenInformation(t, TokenIntegrityLevel, buf, sizeof buf, &n)) { auto* tml = (TOKEN_MANDATORY_LABEL*)buf; ConvertSidToStringSidW(tml->Label.Sid, &s); wprintf(L"IntegrityLevel=%s\n", s); }
    if (GetTokenInformation(t, TokenAppContainerSid, buf, sizeof buf, &n)) { auto* ta = (TOKEN_APPCONTAINER_INFORMATION*)buf; if (ta->TokenAppContainer) { ConvertSidToStringSidW(ta->TokenAppContainer, &s); wprintf(L"AppContainerSid=%s\n", s); } else wprintf(L"AppContainerSid=(none)\n"); }
    if (GetTokenInformation(t, TokenCapabilities, buf, sizeof buf, &n)) { auto* tg = (TOKEN_GROUPS*)buf; wprintf(L"Capabilities=%u\n", tg->GroupCount); for (DWORD i = 0; i < tg->GroupCount; i++) { ConvertSidToStringSidW(tg->Groups[i].Sid, &s); wprintf(L"  %s\n", s); } }
    if (GetTokenInformation(t, TokenGroups, buf, sizeof buf, &n)) { auto* tg = (TOKEN_GROUPS*)buf; wprintf(L"Groups=%u\n", tg->GroupCount); for (DWORD i = 0; i < tg->GroupCount; i++) { ConvertSidToStringSidW(tg->Groups[i].Sid, &s); wprintf(L"  %s attr=0x%X\n", s, tg->Groups[i].Attributes); } }
    DWORD sess = 0; GetTokenInformation(t, TokenSessionId, &sess, sizeof sess, &n); wprintf(L"SessionId=%u\n", sess);
    if (GetTokenInformation(t, TokenPrivileges, buf, sizeof buf, &n)) { auto* tp = (TOKEN_PRIVILEGES*)buf; wprintf(L"Privileges=%u\n", tp->PrivilegeCount); for (DWORD i = 0; i < tp->PrivilegeCount; i++) { wchar_t nm[128]; DWORD l = 128; LookupPrivilegeNameW(nullptr, &tp->Privileges[i].Luid, nm, &l); wprintf(L"  %s attr=0x%X\n", nm, tp->Privileges[i].Attributes); } }
    DWORD elev = 0; GetTokenInformation(t, TokenElevationType, &elev, sizeof elev, &n); wprintf(L"ElevationType=%u\n", elev);
    return 0;
  }
  if (m == L"pipe") { std::wstring nm = std::wstring(L"\\\\.\\pipe\\") + argv[2]; HANDLE h = CreateNamedPipeW(nm.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 4096, 4096, 0, nullptr); R(nm.c_str(), h != INVALID_HANDLE_VALUE); return 0; }
  if (m == L"event") { HANDLE h = CreateEventW(nullptr, TRUE, FALSE, argv[2]); R(argv[2], h != nullptr); return 0; }
  if (m == L"section") { HANDLE h = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 4096, argv[2]); R(argv[2], h != nullptr); return 0; }
  if (m == L"chdir") { R(argv[2], SetCurrentDirectoryW(argv[2])); wchar_t b[1024]; GetCurrentDirectoryW(1024, b); wprintf(L"  cwd now %s\n", b); return 0; }
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
    wprintf(L"NtOpenFile(%s, access=0x%s, options=0x%s) = 0x%08X\n", argv[2], argv[3], argv[4], (unsigned)st); if (h) CloseHandle(h); return 0;
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
  if (m == L"exec") { std::wstring cl; for (int i = 2; i < argc; i++) { if (i > 2) cl += L' '; cl += argv[i]; } STARTUPINFOW si{sizeof si}; PROCESS_INFORMATION pi{}; BOOL ok = CreateProcessW(nullptr, &cl[0], nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi); R(cl.c_str(), ok); if (ok) { WaitForSingleObject(pi.hProcess, INFINITE); DWORD c; GetExitCodeProcess(pi.hProcess, &c); wprintf(L"  exit %u (0x%X)\n", c, c); } return 0; }
  wprintf(L"unknown mode\n"); return 2;
}
