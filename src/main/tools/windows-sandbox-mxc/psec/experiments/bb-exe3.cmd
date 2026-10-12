@echo off
rem exe3: Bazel's tree, native PSEC exe, NO exclusions, busybox-w32 as the shell (+ native Info-ZIP zip on its PATH), directory grants, keep_going.
set JOBS=16
set FLAGS=--keep_going --experimental_use_windows_sandbox=yes --experimental_windows_sandbox_path=C:\mxc\psecexe\BazelSandbox.exe --spawn_strategy=windows-sandbox --shell_executable=C:\mxc\psecexe\tools\bash.exe "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits" --action_env=BAZEL_MXC_DIR_GRANTS=1 --action_env=BAZEL_PSEC_LOG=C:\mxc\log\psecexe-actions-exe3.log
call C:\mxc\psecexe\bb.cmd exe3
