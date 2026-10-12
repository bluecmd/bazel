@echo off
rem exe6 (box): everything sandboxed; busybox (long-path) as genrule shell AND sh toolchain; shell dir granted; trampoline; keep_going.
set JOBS=16
set FLAGS=--keep_going --experimental_use_windows_sandbox=yes --experimental_windows_sandbox_path=C:\mxc\psecexe\BazelSandbox.exe --spawn_strategy=windows-sandbox --shell_executable=C:\mxc\psecexe\tools\bash.exe --repo_env=BAZEL_SH=C:\mxc\psecexe\tools\bash.exe "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools" --action_env=BAZEL_MXC_DIR_GRANTS=1 --action_env=BAZEL_PSEC_TRAMPOLINE=1 --action_env=BAZEL_PSEC_LOG=C:\mxc\log\psecexe-actions-exe6.log
call C:\mxc\psecexe\bb.cmd exe6
