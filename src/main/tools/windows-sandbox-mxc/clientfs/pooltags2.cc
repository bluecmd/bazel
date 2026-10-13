// All pool tags as "tag allocs bytes" lines (paged+nonpaged), for diffing.
#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <vector>
struct Tag { char tag[4]; ULONG pa, pf; SIZE_T pu; ULONG na, nf; SIZE_T nu; };
int main() {
  std::vector<char> buf(1 << 20);
  ULONG len = 0;
  while (NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)22, buf.data(), (ULONG)buf.size(), &len) == (NTSTATUS)0xC0000004)
    buf.resize(buf.size() * 2);
  ULONG count = *(ULONG*)buf.data();
  Tag* t = (Tag*)(buf.data() + sizeof(void*));
  for (ULONG i = 0; i < count; i++) {
    char n[5] = {0};
    for (int k = 0; k < 4; k++) n[k] = (t[i].tag[k] >= 32 && t[i].tag[k] < 127 && t[i].tag[k] != ' ') ? t[i].tag[k] : '_';
    printf("%s %lld %zu\n", n, (long long)t[i].pa - t[i].pf + (long long)t[i].na - t[i].nf, t[i].pu + t[i].nu);
  }
  return 0;
}
