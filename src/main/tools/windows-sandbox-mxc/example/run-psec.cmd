@echo off
rem Runs the example under the in-process windows-psec strategy (see ..\PSEC-JNI.md).
rem Needs a Bazel built from the windows-sandbox-psec-jni branch: set BAZEL to it
rem (and JAVA_HOME if it is a bazel-dev.exe without an embedded JDK). Run from an
rem INTERACTIVE session (console or RDP), not from an SSH shell: in session 0
rem every USER32-importing tool dies with STATUS_DLL_INIT_FAILED inside the
rem security environment regardless of policy.
setlocal
if "%BAZEL%"=="" set BAZEL=bazel
if "%VSROOT%"=="" set VSROOT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools
if "%KITS%"=="" set KITS=C:\Program Files (x86)\Windows Kits
set ROOTS="--experimental_windows_sandbox_readonly_root=%VSROOT%" "--experimental_windows_sandbox_readonly_root=%KITS%"
set NEG=//neg:undeclared_read //neg:undeclared_write //neg:network //neg:undeclared_tool
set LEAK=C:\Users\Public\bazel-mxc-leak.txt
cd /d "%~dp0"
copy /y %SystemRoot%\System32\whoami.exe tools\whoami.exe >NUL
del /q %LEAK% 2>NUL

for %%p in (precise directories coarse) do (
  echo ===== %%p: positive: genrule + cl.exe + link.exe
  %BAZEL% clean >NUL 2>&1
  %BAZEL% build //... --spawn_strategy=windows-psec --experimental_windows_psec_policy=%%p %ROOTS%
  if errorlevel 1 (echo SANDBOXED BUILD FAILED: %%p) else (bazel-bin\hello.exe)
  echo ===== %%p: negative targets, expect 4 failures
  %BAZEL% build %NEG% --keep_going --spawn_strategy=windows-psec --experimental_windows_psec_policy=%%p %ROOTS%
  if exist %LEAK% (echo LEAK: write escaped the sandbox & del /q %LEAK%) else (echo write was contained)
)

echo ===== negative targets, local (expect success)
%BAZEL% build %NEG% --keep_going --spawn_strategy=local
del /q %LEAK% 2>NUL

echo ===== overhead: 40 trivial genrules, --jobs=1 and --jobs=8
for %%j in (1 8) do (
  %BAZEL% clean >NUL 2>&1
  echo local --jobs=%%j
  %BAZEL% build //batch/... --spawn_strategy=local --jobs=%%j 2>&1 | findstr /C:"Elapsed"
  for %%p in (precise directories coarse) do (
    %BAZEL% clean >NUL 2>&1
    echo windows-psec %%p --jobs=%%j
    %BAZEL% build //batch/... --spawn_strategy=windows-psec --experimental_windows_psec_policy=%%p %ROOTS% --jobs=%%j 2>&1 | findstr /C:"Elapsed" /C:"windows-psec ("
  )
)
