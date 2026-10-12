@echo off
rem pmgen3.cmd: the problem genrules (exec-config variants) under Process Monitor, busybox shells + trampoline.
call C:\mxc\psecexe\env.cmd
set PM=C:\mxc\psecexe\tools\Procmon64.exe
set LOG=C:\mxc\log\psecexe-pmgen3.log
del /q C:\mxc\psecexe\gen3.pml C:\mxc\psecexe\gen3.csv 2>NUL
cd /d C:\mxc\bazel-src
echo ===== pmgen3 start %TIME% > %LOG%
start "" %PM% /AcceptEula /Quiet /Minimized /BackingFile C:\mxc\psecexe\gen3.pml
timeout /t 6 >NUL
%BZL% build //src/main/starlark/builtins_bzl:builtins_bzl_zip //src:embedded_jdk_allmodules //third_party:fastutil_stripped_jar //src/main/cpp:jvm_module_options_h --keep_going --verbose_failures %SBX% --shell_executable=C:\mxc\psecexe\tools\bash.exe --repo_env=BAZEL_SH=C:\mxc\psecexe\tools\bash.exe "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools" --action_env=BAZEL_MXC_DIR_GRANTS=1 --action_env=BAZEL_PSEC_TRAMPOLINE=1 >> %LOG% 2>&1
echo exit %ERRORLEVEL% >> %LOG%
%PM% /Terminate
timeout /t 5 >NUL
%PM% /AcceptEula /Quiet /OpenLog C:\mxc\psecexe\gen3.pml /SaveAs C:\mxc\psecexe\gen3.csv
timeout /t 5 >NUL
echo ===== bash.exe failed events >> %LOG%
findstr /i /c:"\"bash.exe\"" C:\mxc\psecexe\gen3.csv | findstr /i /c:"ACCESS DENIED" /c:"PRIVILEGE" /c:"INSUFFICIENT" /c:"INVALID PARAMETER" /c:"SHARING VIOLATION" /c:"NOT FOUND" | findstr /v /c:"Desired Access: Execute/Traverse" /c:"QueryRemoteProtocol" /c:"RegOpenKey" /c:"RegQueryValue" /c:".mun" /c:"SystemResources" >> %LOG%
echo ===== bash.exe process starts >> %LOG%
findstr /i /c:"\"bash.exe\"" C:\mxc\psecexe\gen3.csv | findstr /i /c:"Process Start" /c:"Process Create" /c:"Process Exit" >> %LOG%
echo PMGEN3 DONE >> %LOG%
