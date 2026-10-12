@echo off
call C:\mxc\psecexe\env.cmd
set BB=C:\mxc\psecexe\tools\bash.exe
set SB=C:\mxc\psecexe\BazelSandbox.exe
set BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools
set BAZEL_MXC_DIR_GRANTS=1
set O=C:\mxc\psecexe\t\out
cd /d C:\mxc\ob\zimdgeq3\execroot\_main
echo ===== 1 stdin NUL, stdout/stderr to files
%SB% @C:\mxc\psecexe\fastutil.params -- %BB% -c "x=$(echo hi); echo got $x" < NUL > %O%\o1.txt 2> %O%\e1.txt
echo rc=%ERRORLEVEL% & type %O%\o1.txt %O%\e1.txt
echo ===== 2 stdin from a pipe
echo | %SB% @C:\mxc\psecexe\fastutil.params -- %BB% -c "x=$(echo hi); echo got $x"
echo rc=%ERRORLEVEL%
echo ===== 3 stdout to a pipe
%SB% @C:\mxc\psecexe\fastutil.params -- %BB% -c "x=$(echo hi); echo got $x" | findstr /r ".*"
echo rc=%ERRORLEVEL%
echo ===== 4 no sandbox, stdin NUL, files
set BAZEL_PSEC_NO_SANDBOX=1
%SB% @C:\mxc\psecexe\fastutil.params -- %BB% -c "x=$(echo hi); echo got $x" < NUL > %O%\o4.txt 2> %O%\e4.txt
echo rc=%ERRORLEVEL% & type %O%\o4.txt %O%\e4.txt
set BAZEL_PSEC_NO_SANDBOX=
echo ===== 5 cmd child with stdin NUL, files, sandboxed
%SB% @C:\mxc\psecexe\fastutil.params -- cmd.exe /c "cmd.exe /c echo child-ok" < NUL > %O%\o5.txt 2> %O%\e5.txt
echo rc=%ERRORLEVEL% & type %O%\o5.txt %O%\e5.txt
