@echo off
rem exe1: Bazel's tree, native PSEC exe, today's exclusions (Genrule + ProtocAuthenticityCheck local), directory grants.
set JOBS=16
set FLAGS=--keep_going --experimental_use_windows_sandbox=yes --experimental_windows_sandbox_path=C:\mxc\psecexe\BazelSandbox.exe --spawn_strategy=windows-sandbox --strategy=Genrule=local --strategy=ProtocAuthenticityCheck=local "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits" --action_env=BAZEL_MXC_DIR_GRANTS=1 --action_env=BAZEL_PSEC_LOG=C:\mxc\log\psecexe-actions-exe1.log
call C:\mxc\psecexe\bb.cmd exe1
