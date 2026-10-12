@echo off
rem gen2.cmd: gen1 plus --repo_env=BAZEL_SH=busybox so that sh_binary launchers use busybox too; adds the sh test.
call C:\mxc\psecexe\env.cmd
set LOG=C:\mxc\log\psecexe-gen2.log
cd /d C:\mxc\bazel-src
echo ===== gen2 start %DATE% %TIME% > %LOG%
set F=--keep_going --verbose_failures --sandbox_debug %SBX% --shell_executable=C:\mxc\psecexe\tools\bash.exe "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools" --action_env=BAZEL_MXC_DIR_GRANTS=1 --action_env=BAZEL_PSEC_LOG=C:\mxc\log\psecexe-actions-gen2.log --repo_env=BAZEL_SH=C:\mxc\psecexe\tools\bash.exe
%BZL% build //src/main/starlark/builtins_bzl:builtins_bzl_zip //src:embedded_jdk_allmodules //third_party:fastutil_stripped_jar //third_party:filter_netty_dynamic_libs //src/main/cpp:jvm_module_options_h //psectests:sh %F% >> %LOG% 2>&1
echo exit %ERRORLEVEL% >> %LOG%
echo GEN1 DONE %TIME% >> %LOG%
