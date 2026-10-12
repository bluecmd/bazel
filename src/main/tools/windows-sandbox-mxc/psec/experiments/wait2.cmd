@echo off
call C:\mxc\psecexe\env.cmd
set BB=C:\mxc\psecexe\tools\bash.exe
set SB=C:\mxc\psecexe\BazelSandbox.exe
set NT=C:\mxc\psecexe\nttest.exe
set BAZEL_MXC_EXTRA_RO=C:\mxc\psecexe\tools
set BAZEL_MXC_DIR_GRANTS=1
set T=C:\mxc\psecexe\t
cd /d %T%
echo ===== 1 sandboxed: last command sleeps 3 s
echo %TIME%
%SB% -W %T% -r %T%\in -r %NT% -w %T%\out -- %BB% -c "C:/mxc/psecexe/nttest.exe sleep 3000"
echo rc=%ERRORLEVEL% %TIME%
echo ===== 2 sandboxed: prologue + subshell + last command sleeps 3 s
echo %TIME%
%SB% -W %T% -r %T%\in -r %NT% -w %T%\out -- %BB% -c "source in/setup.sh; x=$(echo hi); C:/mxc/psecexe/nttest.exe sleep 3000"
echo rc=%ERRORLEVEL% %TIME%
echo ===== 3 sandboxed: not last
echo %TIME%
%SB% -W %T% -r %T%\in -r %NT% -w %T%\out -- %BB% -c "source in/setup.sh; x=$(echo hi); C:/mxc/psecexe/nttest.exe sleep 3000; echo after"
echo rc=%ERRORLEVEL% %TIME%
echo ===== 4 no sandbox: same as 2
set BAZEL_PSEC_NO_SANDBOX=1
echo %TIME%
%SB% -W %T% -r %T%\in -r %NT% -w %T%\out -- %BB% -c "source in/setup.sh; x=$(echo hi); C:/mxc/psecexe/nttest.exe sleep 3000"
echo rc=%ERRORLEVEL% %TIME%
set BAZEL_PSEC_NO_SANDBOX=
echo ===== 5 sandboxed, cmd.exe as the shell: cmd /c nttest sleep
echo %TIME%
%SB% -W %T% -r %T%\in -r %NT% -w %T%\out -- cmd.exe /c "C:\mxc\psecexe\nttest.exe sleep 3000"
echo rc=%ERRORLEVEL% %TIME%
