@echo off
rem Builds BazelSandbox.exe (native PSEC) with the VS 2022 Build Tools.
setlocal
for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSPATH=%%i
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
set OUT=%1
if "%OUT%"=="" set OUT=BazelSandbox.exe
cl /nologo /std:c++17 /EHsc /O2 /W3 /DUNICODE /D_UNICODE BazelSandbox.cpp /Fe:%OUT% /link /SUBSYSTEM:CONSOLE
echo BUILD_RC=%ERRORLEVEL%
