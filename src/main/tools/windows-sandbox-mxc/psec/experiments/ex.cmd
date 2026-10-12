@echo off
rem ex.cmd: the example workspace through the native PSEC BazelSandbox.exe (interactive session).
call C:\mxc\psecexe\env.cmd
set LOG=C:\mxc\log\psecexe-ex.log
set NEG=//neg:undeclared_read //neg:undeclared_write //neg:network //neg:undeclared_tool
set LEAK=C:\Users\Public\bazel-mxc-leak.txt
cd /d C:\mxc\ex2\example
for %%d in (bazel-example bazel-bin bazel-out bazel-testlogs) do rmdir %%d 2>NUL
echo ===== ex start %DATE% %TIME% > %LOG%
copy /y %SystemRoot%\System32\whoami.exe tools\whoami.exe >NUL
del /q %LEAK% 2>NUL
echo ===== positive: genrule + cl.exe + link.exe, sandboxed >> %LOG%
%BZL% build //... %SBX% >> %LOG% 2>&1
echo build exit %ERRORLEVEL% >> %LOG%
bazel-bin\hello.exe >> %LOG% 2>&1
echo ===== negative targets, sandboxed (expect 4 failures) >> %LOG%
%BZL% build %NEG% --keep_going %SBX% >> %LOG% 2>&1
if exist %LEAK% (echo LEAK: write escaped the sandbox >> %LOG%) else (echo write was contained >> %LOG%)
echo ===== negative targets, local (expect success) >> %LOG%
%BZL% build %NEG% --keep_going --spawn_strategy=local >> %LOG% 2>&1
del /q %LEAK% 2>NUL
echo ===== overhead: 40 trivial genrules, local vs sandboxed, --jobs=1 >> %LOG%
%BZL% clean >NUL 2>&1
%BZL% build //batch/... --spawn_strategy=local --jobs=1 2>&1 | findstr /C:"Elapsed" >> %LOG%
%BZL% clean >NUL 2>&1
%BZL% build //batch/... %SBX% --jobs=1 2>&1 | findstr /C:"Elapsed" >> %LOG%
%BZL% shutdown >> %LOG% 2>&1
echo EX DONE %TIME% >> %LOG%
