@echo off
set T=C:\mxc\psecexe\t
set SB=C:\mxc\psecexe\BazelSandbox2.exe -W %T% -r C:\mxc\psecexe\tools -r %T%\in -w %T%\out --
cd /d %T%
del /q out\z.zip 2>NUL
echo ===== native zip inside PSEC: create, delete an entry, list (as //third_party:filter_netty_dynamic_libs does)
%SB% C:\mxc\psecexe\tools\zip.exe -q out\z.zip in\a.txt in\setup.sh
echo rc=%ERRORLEVEL%
%SB% C:\mxc\psecexe\tools\zip.exe -qd out\z.zip in/setup.sh
echo rc=%ERRORLEVEL%
%SB% C:\mxc\psecexe\tools\busybox64.exe unzip -l out/z.zip
echo ===== busybox bash with zip on PATH, chmod +w, pipefail prologue
set TMPDIR=%T%\out
%SB% C:\mxc\psecexe\tools\bash.exe -c "set -euo pipefail; export PATH=C:/mxc/psecexe/tools:$PATH; cp in/a.txt out/n.jar && chmod +w out/n.jar && zip -q out/n.jar in/setup.sh && zip -qd out/n.jar in/setup.sh && unzip -l out/n.jar | tail -1; d=$(mktemp -d); echo d=$d; rm -rf $d; echo ok"
echo rc=%ERRORLEVEL%
