@echo off
call C:\mxc\psecexe\env.cmd
set BB=C:\mxc\psecexe\tools\bash.exe
set SB=C:\mxc\psecexe\BazelSandbox.exe
set NT=C:\mxc\psecexe\nttest.exe
set BAZEL_MXC_EXTRA_RO=C:\mxc\psecexe\tools
set T=C:\mxc\psecexe\t
cd /d %T%
echo ===== 1 busybox ps inside the sandbox (process enumeration)
%SB% -W %T% -r %T%\in -r %NT% -w %T%\out -- %BB% -c "ps; echo ppid-check-done"
echo ===== 2 trampoline: last command sleeps 3 s (expect slept + 3 s)
set BAZEL_PSEC_TRAMPOLINE=1
echo %TIME%
%SB% -W %T% -r %T%\in -r %NT% -w %T%\out -- %BB% -c "source in/setup.sh; x=$(echo hi); C:/mxc/psecexe/nttest.exe sleep 3000"
echo rc=%ERRORLEVEL% %TIME%
echo ===== 3 trampoline: ps
%SB% -W %T% -r %T%\in -r %NT% -w %T%\out -- %BB% -c "ps"
set BAZEL_PSEC_TRAMPOLINE=
