@echo off
rem kd-setup.cmd: prepare the debug guest: tools in C:\kd, a 4096-file tree, params files for N-file policies, a writable out dir.
mkdir C:\kd 2>NUL
mkdir C:\kd\out 2>NUL
cd /d C:\kd
ver
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v UBR
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion
dir C:\Windows\System32\drivers\bfs.sys C:\Windows\System32\processmodel.dll 2>&1 | findstr /i "bfs.sys processmodel"
nttest.exe mkfiles C:\kd\files 4096
for %%n in (1 100 1000 4000) do nttest.exe listfiles C:\kd\files %%n > C:\kd\p%%n.params
echo -r> C:\kd\pdir.params
echo C:\kd\files>> C:\kd\pdir.params
dir /b C:\kd
