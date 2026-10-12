@echo off
rem bb.cmd <name>: clean build of //src:bazel-dev.exe in C:\mxc\bazel-src; extra flags from %FLAGS%.
set NAME=%1
if "%JOBS%"=="" set JOBS=8
call C:\mxc\psecexe\env.cmd
set LOG=C:\mxc\log\psecexe-bb-%NAME%.log
set PROF=C:\mxc\prof
set COMMON=--jobs=%JOBS% --profile=%PROF%\psecexe-%NAME%.profile.gz --noslim_profile --experimental_profile_include_target_label --execution_log_compact_file=%PROF%\psecexe-%NAME%.spawnlog.zst --announce_rc
cd /d C:\mxc\bazel-src
echo ===== bb %NAME% start %DATE% %TIME% > %LOG%
echo flags: %FLAGS% >> %LOG%
%BZL% clean >> %LOG% 2>&1
echo ===== build %TIME% >> %LOG%
set T0=%TIME%
%BZL% build //src:bazel-dev.exe %COMMON% %FLAGS% >> %LOG% 2>&1
echo build exit %ERRORLEVEL% start %T0% end %TIME% >> %LOG%
dir bazel-bin\src\bazel-dev.exe >> %LOG% 2>&1
%BZL% shutdown >> %LOG% 2>&1
echo BB %NAME% DONE >> %LOG%
