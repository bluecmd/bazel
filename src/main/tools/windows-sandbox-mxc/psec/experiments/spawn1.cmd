@echo off
set T=C:\mxc\psecexe\t
set G=-r C:\mxc\psecexe\tools -r %T%\in -w %T%\out
set BB=C:\mxc\psecexe\tools\bash.exe
set SB=C:\mxc\psecexe\BazelSandbox.exe
echo ===== 1 busybox subshell, cwd = enumerate-only dir
%SB% -W %T% %G% -- %BB% -c "x=$(echo hi); echo got $x"
echo rc=%ERRORLEVEL%
echo ===== 2 cwd = read-only dir
%SB% -W %T%\in %G% -- %BB% -c "x=$(echo hi); echo got $x"
echo rc=%ERRORLEVEL%
echo ===== 3 cwd = read-write dir
%SB% -W %T%\out %G% -- %BB% -c "x=$(echo hi); echo got $x"
echo rc=%ERRORLEVEL%
echo ===== 4 cmd.exe spawning cmd.exe, cwd = enumerate-only dir
%SB% -W %T% %G% -- cmd.exe /c "cmd.exe /c echo child-ok"
echo rc=%ERRORLEVEL%
echo ===== 5 nttest exec of cmd, cwd = enumerate-only dir
%SB% -W %T% %G% -r C:\mxc\psecexe\nttest.exe -- C:\mxc\psecexe\nttest.exe exec cmd.exe /c "echo child2-ok"
echo ===== 6 busybox with cwd enum-only but TMPDIR granted and pipe
set TMPDIR=%T%\out
%SB% -W %T% %G% -- %BB% -c "echo a | tr a b"
echo rc=%ERRORLEVEL%
