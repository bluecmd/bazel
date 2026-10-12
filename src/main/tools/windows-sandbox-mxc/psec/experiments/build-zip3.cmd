@echo off
for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSPATH=%%i
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d C:\mxc\psecexe\zipsrc\zip30
del /q *.obj zip.exe 2>NUL
cl -nologo -c -W1 -O2 -DWIN32 -DNO_ASM -DNO_LARGE_FILE_SUPPORT -I. -Iwin32 zip.c crypt.c ttyio.c zipfile.c zipup.c fileio.c util.c crc32.c globals.c deflate.c trees.c win32\win32.c win32\win32zip.c win32\nt.c win32\win32i64.c > ..\cl.log 2>&1
echo CL_RC=%ERRORLEVEL%
findstr /c:" error " ..\cl.log
rc -nologo -fo zip.res win32\zip.rc >NUL 2>&1
link -nologo user32.lib advapi32.lib /INCREMENTAL:NO /RELEASE /DYNAMICBASE /OUT:zip.exe zip.obj crypt.obj ttyio.obj zipfile.obj zipup.obj fileio.obj util.obj crc32.obj globals.obj deflate.obj trees.obj win32.obj win32zip.obj nt.obj win32i64.obj zip.res
echo LINK_RC=%ERRORLEVEL%
cd /d C:\mxc\psecexe\t
del /q out\z3.zip 2>NUL
..\zipsrc\zip30\zip.exe -q out\z3.zip in\a.txt in\setup.sh
echo create rc=%ERRORLEVEL%
..\zipsrc\zip30\zip.exe -qd out\z3.zip in/setup.sh
echo delete rc=%ERRORLEVEL%
C:\mxc\psecexe\tools\busybox64.exe unzip -l out/z3.zip
if "%ERRORLEVEL%"=="0" copy /y ..\zipsrc\zip30\zip.exe C:\mxc\psecexe\tools\zip.exe >NUL
