@echo off
rem stress1.cmd: 16 concurrent busybox subshell spawns inside environments, 10 rounds; count failures.
call C:\mxc\psecexe\env.cmd
set BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools
set BAZEL_MXC_DIR_GRANTS=1
set O=C:\mxc\psecexe\t\stress
rmdir /s /q %O% 2>NUL
mkdir %O%
cd /d C:\mxc\ob\zimdgeq3\execroot\_main
for /l %%r in (1,1,10) do (
  for /l %%i in (1,1,16) do start /b "" C:\mxc\psecexe\stress-one.cmd %O%\o-%%r-%%i.txt
  timeout /t 4 >NUL
)
timeout /t 8 >NUL
echo ===== results: files, ok, unable-to-spawn
dir /b %O% | find /c /v ""
findstr /m /c:"got hi a/b" %O%\*.txt | find /c /v ""
findstr /m /c:"unable to spawn" %O%\*.txt | find /c /v ""
findstr /c:"rc=" %O%\*.txt | findstr /v /c:"rc=0"
type %O%\o-1-1.txt
