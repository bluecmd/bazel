@echo off
setlocal
set T=C:\mxc\psecexe\t
set SB=C:\mxc\psecexe\BazelSandbox.exe
set GIT=C:\Program Files\Git
echo ===== A: git-bash -c "echo hi" inside PSEC, Git root read-only
%SB% -r "%GIT%" -w %T%\out -- "%GIT%\usr\bin\bash.exe" -c "echo hi from bash"
echo rc=%ERRORLEVEL%
echo ===== B: same without sandbox
set BAZEL_PSEC_NO_SANDBOX=1
%SB% -r "%GIT%" -w %T%\out -- "%GIT%\usr\bin\bash.exe" -c "echo hi from bash"
echo rc=%ERRORLEVEL%
set BAZEL_PSEC_NO_SANDBOX=
echo ===== C: busybox sh inside PSEC
%SB% -r C:\mxc\psecexe\tools -w %T%\out -- C:\mxc\psecexe\tools\busybox64.exe sh -c "echo hi from busybox; cp /c/mxc/psecexe/t/in/a.txt /c/mxc/psecexe/t/out/bb.txt && cat /c/mxc/psecexe/t/out/bb.txt; ls /c/mxc/psecexe/t/in"
echo rc=%ERRORLEVEL%
echo ===== D: busybox pipe + subshell + mktemp inside PSEC
%SB% -r C:\mxc\psecexe\tools -r %T%\in -w %T%\out -- C:\mxc\psecexe\tools\busybox64.exe sh -c "echo a b c | tr ' ' '\n' | wc -l; d=$(mktemp -d); echo tmp=$d; echo x > $d/f && cat $d/f; rm -rf $d; (cd /c/mxc/psecexe/t/in && pwd)"
echo rc=%ERRORLEVEL%
