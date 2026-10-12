@echo off
setlocal
set T=C:\mxc\psecexe\t
set SB=C:\mxc\psecexe\BazelSandbox.exe -r C:\mxc\psecexe\nttest.exe -r %T%\in -w %T%\out --
set NT=C:\mxc\psecexe\nttest.exe
mkdir %T%\out 2>NUL
echo ===== token
%SB% %NT% token
echo ===== pipes
%SB% %NT% pipe psectest1
%SB% %NT% pipe LOCAL\psectest2
%SB% %NT% pipe msys-1888ae32e00d56aa-1-2
echo ===== events / sections
%SB% %NT% event psecevt1
%SB% %NT% event Global\psecevt2
%SB% %NT% section psecsec1
%SB% %NT% section Global\psecsec2
echo ===== chdir
%SB% %NT% chdir %T%\in
%SB% %NT% chdir %T%
%SB% %NT% chdir %T%\out
%SB% %NT% chdir C:\mxc
echo ===== cmd cd into ro dir / enum dir
%SB% cmd /c "cd /d %T%\in && cd"
%SB% cmd /c "cd /d %T% && cd && dir /b"
echo ===== open modes on a ro dir, enum dir, rw dir, ro file
%SB% %NT% open %T%\in d
%SB% %NT% open %T%\in t
%SB% %NT% open %T%\in a
%SB% %NT% open %T% d
%SB% %NT% open %T% t
%SB% %NT% open %T% a
%SB% %NT% open %T%\out d
%SB% %NT% open %T%\in\a.txt r
%SB% %NT% open %T%\in\a.txt x
%SB% %NT% open %T%\in\a.txt w
echo ===== links inside the rw dir
%SB% %NT% symlink %T%\out\sl-file.txt %T%\in\a.txt f
%SB% %NT% symlink %T%\out\sl-dir %T%\in d
%SB% %NT% junction %T%\out\junc %T%\in
%SB% %NT% hardlink %T%\out\hl.txt %T%\in\a.txt
%SB% %NT% mkdir %T%\out\sub
dir %T%\out
echo ===== same links WITHOUT sandbox (for comparison)
set BAZEL_PSEC_NO_SANDBOX=1
%NT% symlink %T%\out\sl2-file.txt %T%\in\a.txt f
%NT% junction %T%\out\junc2 %T%\in
set BAZEL_PSEC_NO_SANDBOX=
dir %T%\out
rmdir /s /q %T%\out 2>NUL
