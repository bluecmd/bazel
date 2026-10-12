@echo off
call C:\mxc\psecexe\env.cmd
set BB=C:\mxc\psecexe\tools\bash.exe
set SB=C:\mxc\psecexe\BazelSandbox.exe
set BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools
set BAZEL_MXC_DIR_GRANTS=1
set BAZEL_PSEC_TRAMPOLINE=1
cd /d C:\mxc\ob\zimdgeq3\execroot\_main
echo ===== 1 upb grants + trampoline: dirname subshell, policy shown
%SB% -D @C:\mxc\psecexe\upb.params -- %BB% -c "echo d=$(dirname external/protobuf+/src/google/protobuf/descriptor.proto)" 2>&1 | findstr /v /c:"  enum"
echo rc=%ERRORLEVEL%
echo ===== 2 same, stdin from NUL and stdout to a file (as under Bazel)
%SB% @C:\mxc\psecexe\upb.params -- %BB% -c "echo d=$(dirname external/protobuf+/src/google/protobuf/descriptor.proto)" < NUL > C:\mxc\psecexe\t\out\upb2.txt 2>&1
echo rc=%ERRORLEVEL%
type C:\mxc\psecexe\t\out\upb2.txt
echo ===== 3 trampoline, nttest stat of bash.exe with reparse flag inside
%SB% @C:\mxc\psecexe\upb.params -r C:\mxc\psecexe\nttest.exe -- C:\mxc\psecexe\nttest.exe ntopen C:\mxc\psecexe\tools\bash.exe 80 200000
