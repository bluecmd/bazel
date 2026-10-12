@echo off
rem kd-trace.cmd: one environment creation (300 paths) + 300 x 3 sandboxed opens under the psec.wprp profile; CSV dump for conversion.
cd /d C:\kd
echo ===== TRACE start %TIME% > C:\kd\trace.log
nttest.exe listfiles C:\kd\files 300 > C:\kd\p300.params
del /q C:\kd\psec.etl C:\kd\psec.csv C:\kd\psec.csv.gz 2>NUL
wpr -start C:\kd\psec.wprp!Psec -filemode >> C:\kd\trace.log 2>&1
set BAZEL_MXC_TIMING=C:\kd\timing-trace.txt
del /q %BAZEL_MXC_TIMING% 2>NUL
C:\kd\BazelSandbox.exe -W C:\kd -r C:\kd\nttest.exe @C:\kd\p300.params -w C:\kd\out -- C:\kd\nttest.exe openloop C:\kd\files 300 3 >> C:\kd\trace.log 2>&1
echo rc=%ERRORLEVEL% >> C:\kd\trace.log
wpr -stop C:\kd\psec.etl >> C:\kd\trace.log 2>&1
type %BAZEL_MXC_TIMING% >> C:\kd\trace.log
tracerpt C:\kd\psec.etl -o C:\kd\psec.csv -of CSV -y >> C:\kd\trace.log 2>&1
tar -czf C:\kd\psec.csv.gz -C C:\kd psec.csv
for %%f in (C:\kd\psec.etl C:\kd\psec.csv C:\kd\psec.csv.gz) do @echo %%~zf %%f >> C:\kd\trace.log
echo TRACE DONE >> C:\kd\trace.log
