@echo off
rem tests2.cmd: the four tests sandboxed with busybox as genrule shell + sh toolchain + trampoline (VM).
call C:\mxc\psecexe\env.cmd
set LOG=C:\mxc\log\psecexe-tests2.log
cd /d C:\mxc\bazel-src
echo ===== tests2 start %DATE% %TIME% > %LOG%
%BZL% test //psectests:cc //psectests:java //psectests:py //psectests:sh --keep_going --test_output=all --jobs=8 %SBX% --shell_executable=C:\mxc\psecexe\tools\bash.exe --repo_env=BAZEL_SH=C:\mxc\psecexe\tools\bash.exe "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools" --action_env=BAZEL_MXC_DIR_GRANTS=1 --action_env=BAZEL_PSEC_TRAMPOLINE=1 >> %LOG% 2>&1
echo exit %ERRORLEVEL% >> %LOG%
echo TESTS2 DONE >> %LOG%
