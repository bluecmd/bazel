// bnodir.exe: experiments with NT object directories for the MSYS-in-PSEC question.
//   bnodir acl <ntpath>            print the DACL of an object directory
//   bnodir hold <ntpath> [secs]    create <ntpath> (OBJ_OPENIF, permissive DACL incl. ALL APPLICATION PACKAGES) and keep it alive
//   bnodir list <ntpath>           list a directory object's entries
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <cstdio>
#include <string>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
typedef NTSTATUS(NTAPI* NtCreateDirectoryObject_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* NtOpenDirectoryObject_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* NtQuerySecurityObject_t)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtQueryDirectoryObject_t)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
struct DBI { UNICODE_STRING Name, Type; };
#define DIRECTORY_QUERY 1
#define DIRECTORY_ALL 0xF000F
int wmain(int argc, wchar_t** argv) {
  if (argc < 3) { wprintf(L"usage: bnodir acl|hold|list <ntpath> [secs]\n"); return 2; }
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  auto Create = (NtCreateDirectoryObject_t)GetProcAddress(nt, "NtCreateDirectoryObject");
  auto Open = (NtOpenDirectoryObject_t)GetProcAddress(nt, "NtOpenDirectoryObject");
  auto QSec = (NtQuerySecurityObject_t)GetProcAddress(nt, "NtQuerySecurityObject");
  auto QDir = (NtQueryDirectoryObject_t)GetProcAddress(nt, "NtQueryDirectoryObject");
  UNICODE_STRING us; RtlInitUnicodeString(&us, argv[2]);
  OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &us, OBJ_OPENIF, nullptr, nullptr);
  std::wstring mode = argv[1];
  HANDLE h = nullptr; NTSTATUS st;
  if (mode == L"hold") {
    PSECURITY_DESCRIPTOR sd = nullptr; ULONG sdlen = 0;
    // Everyone, ALL APPLICATION PACKAGES, ALL RESTRICTED APPLICATION PACKAGES: full (GA); Blue/mxc implicit via WD.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;WD)(A;;GA;;;AC)(A;;GA;;;S-1-15-2-2)", SDDL_REVISION_1, &sd, &sdlen)) { wprintf(L"sddl failed %u\n", GetLastError()); return 1; }
    oa.SecurityDescriptor = sd;
    st = Create(&h, DIRECTORY_ALL, &oa);
    wprintf(L"NtCreateDirectoryObject(%s) = 0x%08X%s\n", argv[2], (unsigned)st, st == 0x40000000 ? L" (opened existing)" : L"");
    if (st < 0) return 1;
    int secs = argc > 3 ? _wtoi(argv[3]) : 3600;
    fflush(stdout);
    Sleep(secs * 1000);
    return 0;
  }
  st = Open(&h, DIRECTORY_QUERY | READ_CONTROL, &oa);
  wprintf(L"NtOpenDirectoryObject(%s) = 0x%08X\n", argv[2], (unsigned)st);
  if (st < 0) return 1;
  if (mode == L"acl") {
    BYTE buf[4096]; ULONG need = 0;
    st = QSec(h, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, buf, sizeof buf, &need);
    wprintf(L"NtQuerySecurityObject = 0x%08X\n", (unsigned)st);
    if (st >= 0) { LPWSTR s = nullptr; if (ConvertSecurityDescriptorToStringSecurityDescriptorW(buf, SDDL_REVISION_1, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, &s, nullptr)) wprintf(L"%s\n", s); }
  } else if (mode == L"list") {
    BYTE buf[65536]; ULONG ctx = 0, ret = 0; BOOLEAN restart = TRUE;
    while (true) {
      st = QDir(h, buf, sizeof buf, FALSE, restart, &ctx, &ret);
      if (st < 0 && st != 0x105) { wprintf(L"NtQueryDirectoryObject = 0x%08X\n", (unsigned)st); break; }
      for (DBI* e = (DBI*)buf; e->Name.Buffer; ++e) wprintf(L"  %-20.*s %.*s\n", e->Type.Length / 2, e->Type.Buffer, e->Name.Length / 2, e->Name.Buffer);
      if (st != 0x105) break;
      restart = FALSE;
    }
  }
  return 0;
}
