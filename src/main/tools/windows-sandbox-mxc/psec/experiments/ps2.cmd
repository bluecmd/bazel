@echo off
setlocal
set T=C:\mxc\psecexe\t
set SB=C:\mxc\psecexe\BazelSandbox.exe -W %T% -r C:\mxc\psecexe\pipetest.ps1 -r %T%\in -w %T%\out --
echo ===== Bazel cmd_ps prologue + read of a granted input + write of an output
%SB% powershell.exe -NoProfile -Command "Set-ExecutionPolicy -Scope CurrentUser RemoteSigned; $errorActionPreference='Stop'; $PSDefaultParameterValues['*:Encoding'] = 'utf8'; $v = (Get-Content in/a.txt) -join ''; Set-Content -NoNewline -Path out/ps2.txt -Value \"v=$v\"; Get-Content out/ps2.txt"
echo rc=%ERRORLEVEL%
echo ===== prologue without Set-ExecutionPolicy
%SB% powershell.exe -NoProfile -Command "$errorActionPreference='Stop'; $v = (Get-Content in/a.txt) -join ''; Set-Content -NoNewline -Path out/ps3.txt -Value \"v=$v\"; Get-Content out/ps3.txt"
echo rc=%ERRORLEVEL%
echo ===== -File on a granted script
%SB% powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\mxc\psecexe\pipetest.ps1
echo rc=%ERRORLEVEL%
