@echo off
setlocal
set T=C:\mxc\psecexe\t
set SB=C:\mxc\psecexe\BazelSandbox.exe -r C:\mxc\psecexe\nttest.exe -r %T%\in -w %T%\out --
set NT=C:\mxc\psecexe\nttest.exe
mkdir %T%\out 2>NUL
echo ===== NtOpenFile matrix on ro dir 'in' (access, options): 100000=SYNCHRONIZE 20=TRAVERSE 1=LIST 80=READ_ATTR ; options 1=DIRECTORY_FILE 20=SYNC_IO_NONALERT 4000=BACKUP_INTENT
for %%a in (20 100020 1 100001 80 100080 100000) do for %%o in (0 1 21 4021 4000) do %SB% %NT% ntopen %T%\in %%a %%o
echo ===== same on the enumerate-only dir 't'
for %%a in (20 100020 1 100001 80) do for %%o in (0 1 21 4021) do %SB% %NT% ntopen %T% %%a %%o
echo ===== same on the rw dir 'out'
for %%a in (20 100020 1 100001) do for %%o in (1 21 4021) do %SB% %NT% ntopen %T%\out %%a %%o
echo ===== hardlink to an rw file; developer mode state
echo x> %T%\out\src.txt
%SB% %NT% hardlink %T%\out\hl2.txt %T%\out\src.txt
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock /v AllowDevelopmentWithoutDevLicense
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 1 /f
%SB% %NT% symlink %T%\out\sl3.txt %T%\out\src.txt f
%SB% %NT% symlink %T%\out\sl3-dir %T%\in d
dir %T%\out
