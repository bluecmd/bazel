@echo off
setlocal
set T=C:\mxc\psecexe\t
set SB=C:\mxc\psecexe\BazelSandbox.exe
set GIT=C:\Program Files\Git
set BB=C:\mxc\psecexe\tools\busybox64.exe
set KEY=msys-2.0S5-1888ae32e00d56aa
del /q %T%\out\* 2>NUL
echo ===== hold the two MSYS directory objects with an AppContainer-friendly DACL
start /b C:\mxc\psecexe\bnodir.exe hold \BaseNamedObjects\%KEY% 300
start /b C:\mxc\psecexe\bnodir.exe hold \Sessions\1\BaseNamedObjects\%KEY% 300
timeout /t 2 >NUL
C:\mxc\psecexe\bnodir.exe acl \BaseNamedObjects\%KEY%
echo ===== A1: bash -c echo, inside PSEC, with the directories pre-created
%SB% -r "%GIT%" -r %T%\in -w %T%\out -- "%GIT%\usr\bin\bash.exe" -c "echo hi from bash"
echo rc=%ERRORLEVEL%
echo ===== A2: bash pipeline, command substitution, cp, cat, ls, subshell
%SB% -r "%GIT%" -r %T%\in -w %T%\out -- "%GIT%\usr\bin\bash.exe" -c "set -euo pipefail; echo a | tr a b; x=$(echo sub); echo x=$x; cp /c/mxc/psecexe/t/in/a.txt /c/mxc/psecexe/t/out/b.txt; cat /c/mxc/psecexe/t/out/b.txt; (cd /c/mxc/psecexe/t/in && pwd); ls /c/mxc/psecexe/t/out; d=$(mktemp -d); echo d=$d; echo y > $d/f; cat $d/f; rm -rf $d"
echo rc=%ERRORLEVEL%
echo ===== A3: bash with the genrule-setup prologue and a redirect, cwd = t
%SB% -W %T% -r "%GIT%" -r %T%\in -w %T%\out -- "%GIT%\usr\bin\bash.exe" -c "source /c/mxc/psecexe/t/in/setup.sh; cat in/a.txt > out/c.txt && cat out/c.txt"
echo rc=%ERRORLEVEL%
echo ===== list what MSYS put in the directory
C:\mxc\psecexe\bnodir.exe list \BaseNamedObjects\%KEY%
C:\mxc\psecexe\bnodir.exe list \Sessions\1\BaseNamedObjects\%KEY%
echo ===== C: busybox sh inside PSEC (Windows paths, TMPDIR granted)
set TMPDIR=%T%\out
%SB% -W %T% -r C:\mxc\psecexe\tools -r %T%\in -w %T%\out -- %BB% sh -c "set -euo pipefail; echo hi from busybox; cp in/a.txt out/bb.txt && cat out/bb.txt; ls in; echo a b c | tr ' ' '\n' | wc -l; d=$(mktemp -d); echo tmp=$d; echo x > $d/f && cat $d/f; rm -rf $d; (cd in && pwd); dirname in/a.txt; find in -type f | xargs -n1 echo found"
echo rc=%ERRORLEVEL%
set TMPDIR=
taskkill /f /im bnodir.exe >NUL 2>&1
