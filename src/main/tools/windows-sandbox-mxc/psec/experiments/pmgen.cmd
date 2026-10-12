@echo off
rem pmgen.cmd: the fastutil genrule under Process Monitor (busybox shell, sandboxed), then list busybox's failed events.
call C:\mxc\psecexe\env.cmd
set PM=C:\mxc\psecexe\tools\Procmon64.exe
set LOG=C:\mxc\log\psecexe-pmgen.log
del /q C:\mxc\psecexe\gen.pml C:\mxc\psecexe\gen.csv 2>NUL
cd /d C:\mxc\bazel-src
echo ===== pmgen start %TIME% > %LOG%
start "" %PM% /AcceptEula /Quiet /Minimized /BackingFile C:\mxc\psecexe\gen.pml
timeout /t 6 >NUL
%BZL% build //third_party:fastutil_stripped_jar --verbose_failures %SBX% --shell_executable=C:\mxc\psecexe\tools\bash.exe "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools" --action_env=BAZEL_MXC_DIR_GRANTS=1 >> %LOG% 2>&1
echo exit %ERRORLEVEL% >> %LOG%
%PM% /Terminate
timeout /t 5 >NUL
%PM% /AcceptEula /Quiet /OpenLog C:\mxc\psecexe\gen.pml /SaveAs C:\mxc\psecexe\gen.csv
timeout /t 5 >NUL
echo ===== bash.exe events that are not SUCCESS >> %LOG%
findstr /i /c:"\"bash.exe\"" C:\mxc\psecexe\gen.csv | findstr /v /c:"SUCCESS" | findstr /v /c:"NAME NOT FOUND" | findstr /v /c:"FAST IO" | findstr /v /c:"BUFFER OVERFLOW" | findstr /v /c:"END OF FILE" | findstr /v /c:"NO MORE" | findstr /v /c:"REPARSE" | findstr /v /c:"RegQueryValue" | findstr /v /c:"RegOpenKey" >> %LOG%
echo ===== bash.exe Process Create / Start / Exit >> %LOG%
findstr /i /c:"\"bash.exe\"" C:\mxc\psecexe\gen.csv | findstr /i /c:"Process Create" /c:"Process Start" /c:"Process Exit" >> %LOG%
echo PMGEN DONE >> %LOG%
