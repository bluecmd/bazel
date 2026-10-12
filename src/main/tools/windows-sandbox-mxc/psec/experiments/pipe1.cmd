@echo off
setlocal
set T=C:\mxc\psecexe\t
set SB=C:\mxc\psecexe\BazelSandbox.exe
set BB=C:\mxc\psecexe\tools\busybox64.exe
echo ===== named pipes / events inside PSEC (powershell)
%SB% -r C:\mxc\psecexe -w %T%\out -- powershell -NoProfile -ExecutionPolicy Bypass -File C:\mxc\psecexe\pipetest.ps1
echo rc=%ERRORLEVEL%
echo ===== whoami /all inside PSEC
%SB% -r C:\mxc\psecexe -w %T%\out -- whoami /all
echo ===== busybox cd probes
set TMPDIR=%T%\out
%SB% -W %T% -r C:\mxc\psecexe\tools -r %T%\in -w %T%\out -- %BB% sh -c "cd in && pwd; cd ..; (pwd); (cd C:/mxc/psecexe/t/in && pwd); cd C:/mxc/psecexe/t/out && pwd"
echo rc=%ERRORLEVEL%
