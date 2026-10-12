@echo off
set PATH=C:\mxc\bin;C:\Program Files\Git\bin;C:\Program Files\nodejs;%PATH%
set BAZEL_SH=C:\Program Files\Git\usr\bin\bash.exe
set BAZELISK_HOME=C:\mxc\bazelisk
set JAVA_HOME=C:\mxc\jdk
set VSCMD_SKIP_SENDTELEMETRY=1
if "%ADAPTER%"=="" set ADAPTER=C:\mxc\psecexe\BazelSandbox.exe
set VSROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools
set KITS=C:\Program Files (x86)\Windows Kits
set BZL=C:\mxc\bin\bazel-patched.exe --output_user_root=C:\mxc\ob
set SBX=--experimental_use_windows_sandbox=yes --experimental_windows_sandbox_path=%ADAPTER% --spawn_strategy=windows-sandbox "--action_env=BAZEL_MXC_EXTRA_RO=%VSROOT%;%KITS%"
