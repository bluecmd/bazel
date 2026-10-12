@echo off
rem exe2: Bazel's tree, native PSEC exe, NO exclusions (everything through windows-sandbox), directory grants, keep_going.
set JOBS=8
set FLAGS=--keep_going --experimental_use_windows_sandbox=yes --experimental_windows_sandbox_path=C:\mxc\psecexe\BazelSandbox.exe --spawn_strategy=windows-sandbox "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits" --action_env=BAZEL_MXC_DIR_GRANTS=1 --action_env=BAZEL_PSEC_LOG=C:\mxc\log\psecexe-actions-exe2.log
call C:\mxc\psecexe\bb.cmd exe2
