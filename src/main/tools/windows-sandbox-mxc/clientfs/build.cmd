@echo off
setlocal
for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSPATH=%%i
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d C:\mxc\clientfs
cl /nologo /std:c++17 /EHsc /O2 /W3 /DUNICODE /D_UNICODE /I . clientfs_bench.cc src\main\native\windows\psec.cc src\main\native\windows\process.cc src\main\native\windows\util.cc src\main\native\windows\file.cc /Fe:clientfs_bench.exe /link advapi32.lib psapi.lib
echo BUILD_RC=%ERRORLEVEL%
