@echo off
set T=C:\mxc\psecexe\t
set G=-W %T% -r C:\mxc\psecexe\tools -r %T%\in -w %T%\out
set BB=C:\mxc\psecexe\tools\bash.exe
set SB=C:\mxc\psecexe\BazelSandbox.exe
set ENV=C:\mxc\psecexe\tools\busybox64.exe env -i
set P=PATH=C:\mxc\psecexe\tools;C:\WINDOWS;C:\WINDOWS\System32;C:\WINDOWS\System32\WindowsPowerShell\v1.0
echo ===== 1 Bazel's scrubbed environment (PATH, TMP, TEMP, RUNFILES_MANIFEST_ONLY), busybox subshell
%ENV% "%P%" TMP=C:\Users\mxc\AppData\Local\Temp TEMP=C:\Users\mxc\AppData\Local\Temp RUNFILES_MANIFEST_ONLY=1 %SB% %G% -- %BB% -c "x=$(echo hi); echo got $x"
echo rc=%ERRORLEVEL%
echo ===== 2 same plus SystemRoot
%ENV% "%P%" TMP=C:\Users\mxc\AppData\Local\Temp TEMP=C:\Users\mxc\AppData\Local\Temp RUNFILES_MANIFEST_ONLY=1 SystemRoot=C:\WINDOWS %SB% %G% -- %BB% -c "x=$(echo hi); echo got $x"
echo rc=%ERRORLEVEL%
echo ===== 3 scrubbed env, NO sandbox
set BAZEL_PSEC_NO_SANDBOX=1
%ENV% "%P%" TMP=C:\Users\mxc\AppData\Local\Temp TEMP=C:\Users\mxc\AppData\Local\Temp RUNFILES_MANIFEST_ONLY=1 BAZEL_PSEC_NO_SANDBOX=1 %SB% %G% -- %BB% -c "x=$(echo hi); echo got $x"
echo rc=%ERRORLEVEL%
set BAZEL_PSEC_NO_SANDBOX=
echo ===== 4 scrubbed env, cmd spawning cmd inside the sandbox
%ENV% "%P%" TMP=C:\Users\mxc\AppData\Local\Temp TEMP=C:\Users\mxc\AppData\Local\Temp %SB% %G% -- cmd.exe /c "cmd.exe /c echo child-ok"
echo rc=%ERRORLEVEL%
echo ===== 5 scrubbed env + SystemRoot, cmd spawning cmd inside the sandbox
%ENV% "%P%" TMP=C:\Users\mxc\AppData\Local\Temp TEMP=C:\Users\mxc\AppData\Local\Temp SystemRoot=C:\WINDOWS %SB% %G% -- cmd.exe /c "cmd.exe /c echo child-ok"
echo rc=%ERRORLEVEL%
