@echo off
rem kd-prof.cmd <label> <cmd...>: run <cmd> under a WPR CPU sample profile (kernel+user), save C:\kd\<label>.etl and a CSV dump of the samples.
set L=%1
shift
set CMD=%1
:more
shift
if not "%1"=="" (set CMD=%CMD% %1& goto more)
cd /d C:\kd
del /q C:\kd\%L%.etl C:\kd\%L%.csv C:\kd\%L%.csv.gz 2>NUL
wpr -start CPU -filemode
set BAZEL_MXC_TIMING=C:\kd\timing-%L%.txt
del /q %BAZEL_MXC_TIMING% 2>NUL
echo ===== running: %CMD%
%CMD%
echo rc=%ERRORLEVEL%
wpr -stop C:\kd\%L%.etl
type %BAZEL_MXC_TIMING% 2>NUL
tracerpt C:\kd\%L%.etl -o C:\kd\%L%.csv -of CSV -y >NUL
for %%f in (C:\kd\%L%.etl C:\kd\%L%.csv) do @echo %%~zf %%f
tar -czf C:\kd\%L%.csv.gz -C C:\kd %L%.csv
for %%f in (C:\kd\%L%.csv.gz) do @echo %%~zf %%f
