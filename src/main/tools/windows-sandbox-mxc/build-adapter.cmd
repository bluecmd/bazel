@echo off
rem Builds BazelSandbox.exe with the MSVC toolchain found by vswhere, without
rem needing a Bazel bootstrap. Output: BazelSandbox.exe next to this script.
setlocal
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VS=%%i
if "%VS%"=="" (echo vswhere found no MSVC toolchain & exit /b 1)
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >NUL
cd /d "%~dp0"
cl /nologo /W3 /O2 /Fe:BazelSandbox.exe BazelSandbox.c
