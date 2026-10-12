@echo off
for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSPATH=%%i
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d C:\mxc\psecexe\tools
mt -nologo -inputresource:busybox64.exe;#1 -out:bb-orig.manifest >NUL 2>&1
copy /y busybox64.exe busyboxlp.exe >NUL
mt -nologo -manifest bb-orig.manifest C:\mxc\psecexe\bb.manifest -outputresource:busyboxlp.exe;#1
echo MT_RC=%ERRORLEVEL%
reg add HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f >NUL
set P=C:/mxc/ob/zimdgeq3/execroot/_main/external/rules_jvm_external++maven+com_google_guava_listenablefuture_9999_0_empty_to_avoid_conflict_with_guava/file/v1/com/google/guava/listenablefuture/9999.0-empty-to-avoid-conflict-with-guava/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
echo ===== original busybox, LongPathsEnabled=1
busybox64.exe sh -c "ls -l '%P%'"
echo ===== busybox with longPathAware manifest, LongPathsEnabled=1
busyboxlp.exe sh -c "ls -l '%P%' && cp '%P%' C:/mxc/psecexe/t/out/lp.jar && ls -l C:/mxc/psecexe/t/out/lp.jar"
