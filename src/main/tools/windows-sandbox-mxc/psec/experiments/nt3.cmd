@echo off
setlocal
set T=C:\mxc\psecexe\t
set SB=C:\mxc\psecexe\BazelSandbox.exe -r C:\mxc\psecexe\nttest.exe -r %T%\in -w %T%\out --
set NT=C:\mxc\psecexe\nttest.exe
echo y> %T%\out\o.txt
echo ===== FILE_OPEN_REPARSE_POINT 0x200000 matrix on ro file, ro dir, enum dir, rw file; access 80=READ_ATTR 100080=+SYNC 120089=GENERIC_READ; options 0, 200000, 204000=+BACKUP, 200021=+DIR+SYNCIO
for %%p in (%T%\in\a.txt %T%\in %T% %T%\out\o.txt) do for %%a in (80 100080 120089) do for %%o in (0 200000 204000 200021) do %SB% %NT% ntopen %%p %%a %%o
echo ===== cmd/dir/type of the same file for comparison
%SB% cmd /c "type %T%\in\a.txt & dir /b %T%\in"
