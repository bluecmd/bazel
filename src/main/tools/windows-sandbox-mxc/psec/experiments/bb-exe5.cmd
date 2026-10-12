@echo off
rem exe5 (VM): like exe4 (no exclusions, busybox as shell) plus: long-path-aware busybox, the shell's directory granted read-only, runfiles-rw exe.
set JOBS=8
set FLAGS=--keep_going --experimental_use_windows_sandbox=yes --experimental_windows_sandbox_path=C:\mxc\psecexe\BazelSandbox.exe --spawn_strategy=windows-sandbox --shell_executable=C:\mxc\psecexe\tools\bash.exe "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools" --action_env=BAZEL_MXC_DIR_GRANTS=1 --action_env=BAZEL_PSEC_LOG=C:\mxc\log\psecexe-actions-exe5.log
call C:\mxc\psecexe\bb.cmd exe5
