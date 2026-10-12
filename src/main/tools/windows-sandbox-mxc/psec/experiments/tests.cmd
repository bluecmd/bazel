@echo off
rem tests.cmd: bazel test of one cc/java/py/sh test each, sandboxed vs local (VM, interactive session).
set ADAPTER=C:\mxc\psecexe\BazelSandbox2.exe
call C:\mxc\psecexe\env.cmd
set LOG=C:\mxc\log\psecexe-tests.log
cd /d C:\mxc\bazel-src
echo ===== tests start %DATE% %TIME% > %LOG%
set T=//psectests:cc //psectests:java //psectests:py //psectests:sh
echo ===== sandboxed, git-bash as shell >> %LOG%
%BZL% test %T% --keep_going --test_output=all --jobs=8 %SBX% --action_env=BAZEL_MXC_DIR_GRANTS=1 --action_env=BAZEL_PSEC_LOG=C:\mxc\log\psecexe-actions-tests.log >> %LOG% 2>&1
echo exit %ERRORLEVEL% >> %LOG%
echo ===== sandboxed, busybox as shell >> %LOG%
%BZL% test %T% --keep_going --test_output=all --jobs=8 %SBX% --shell_executable=C:\mxc\psecexe\tools\bash.exe --action_env=BAZEL_MXC_DIR_GRANTS=1 --action_env=BAZEL_PSEC_LOG=C:\mxc\log\psecexe-actions-tests.log >> %LOG% 2>&1
echo exit %ERRORLEVEL% >> %LOG%
echo ===== local >> %LOG%
%BZL% test %T% --keep_going --test_output=all --jobs=8 --spawn_strategy=local >> %LOG% 2>&1
echo exit %ERRORLEVEL% >> %LOG%
echo TESTS DONE %TIME% >> %LOG%
