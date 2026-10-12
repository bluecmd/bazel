@echo off
rem stress-one.cmd <outfile>: one sandboxed busybox run with two subshells.
C:\mxc\psecexe\BazelSandbox.exe @C:\mxc\psecexe\fastutil.params -- C:\mxc\psecexe\tools\bash.exe -c "x=$(echo hi); y=$(dirname a/b/c); echo got $x $y" > %1 2>&1
echo rc=%ERRORLEVEL% >> %1
