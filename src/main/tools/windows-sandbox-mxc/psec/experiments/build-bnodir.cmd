@echo off
setlocal
for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSPATH=%%i
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d C:\mxc\psecexe
cl /nologo /std:c++17 /EHsc /O2 /W3 /DUNICODE /D_UNICODE bnodir.cpp /Fe:bnodir.exe
echo BUILD_RC=%ERRORLEVEL%
