@echo off
rem Runs the example through BazelSandbox.exe (MXC adapter). Run this from an
rem INTERACTIVE session (console or RDP), not from an SSH shell: in session 0
rem every USER32-importing tool dies with STATUS_DLL_INIT_FAILED inside the
rem container regardless of policy.
rem
rem Prerequisites: Windows 11 25H2 26200.9550 or later, MXC 1.0.0 (wxc-exec.exe
rem next to BazelSandbox.exe), VS Build Tools with the C++ workload, bazelisk.
setlocal
if "%ADAPTER%"=="" set ADAPTER=%~dp0..\BazelSandbox.exe
if "%VSROOT%"=="" set VSROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools
if "%KITS%"=="" set KITS=C:\Program Files (x86)\Windows Kits
set SBX=--experimental_use_windows_sandbox=yes --experimental_windows_sandbox_path=%ADAPTER% --spawn_strategy=windows-sandbox --action_env=BAZEL_MXC_ENUM_CWD=1 --action_env=BAZEL_MXC_ENUM_ANCESTORS=1 --action_env=BAZEL_MXC_UI=1 "--action_env=BAZEL_MXC_EXTRA_RO=%VSROOT%;%KITS%"
set NEG=//neg:undeclared_read //neg:undeclared_write //neg:network //neg:undeclared_tool
set LEAK=C:\Users\Public\bazel-mxc-leak.txt
cd /d "%~dp0"
copy /y %SystemRoot%\System32\whoami.exe tools\whoami.exe >NUL
del /q %LEAK% 2>NUL

echo ===== positive: genrule + cl.exe + link.exe, sandboxed
bazel build //... %SBX%
if errorlevel 1 (echo SANDBOXED BUILD FAILED & exit /b 1)
bazel-bin\hello.exe

echo ===== negative targets, sandboxed (expect 4 failures)
bazel build %NEG% --keep_going %SBX%
if exist %LEAK% (echo LEAK: write escaped the sandbox) else (echo write was contained)

echo ===== negative targets, local (expect success)
bazel build %NEG% --keep_going --spawn_strategy=local
del /q %LEAK% 2>NUL

echo ===== overhead: 40 trivial genrules, local vs sandboxed, --jobs=1
bazel clean >NUL 2>&1
bazel build //batch/... --spawn_strategy=local --jobs=1 2>&1 | findstr /C:"Elapsed"
bazel clean >NUL 2>&1
bazel build //batch/... %SBX% --jobs=1 2>&1 | findstr /C:"Elapsed"
