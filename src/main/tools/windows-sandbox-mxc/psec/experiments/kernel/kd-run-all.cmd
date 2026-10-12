@echo off
rem kd-run-all.cmd: timings (kd-bench) then four WPR profiles; everything to C:\kd\runall.log
cd /d C:\kd
echo ===== RUNALL start %TIME% > C:\kd\runall.log
call C:\kd\kd-bench.cmd bench >> C:\kd\runall.log 2>&1
echo ===== PROFILE create4000 >> C:\kd\runall.log
call C:\kd\kd-prof.cmd create4000 C:\kd\BazelSandbox.exe -W C:\kd -r C:\kd\nttest.exe @C:\kd\p4000.params -w C:\kd\out -- C:\kd\nttest.exe sleep 100 >> C:\kd\runall.log 2>&1
echo ===== PROFILE open1000 >> C:\kd\runall.log
call C:\kd\kd-prof.cmd open1000 C:\kd\BazelSandbox.exe -W C:\kd -r C:\kd\nttest.exe @C:\kd\p1000.params -w C:\kd\out -- C:\kd\nttest.exe openloop C:\kd\files 1000 30 >> C:\kd\runall.log 2>&1
echo ===== PROFILE opendir >> C:\kd\runall.log
call C:\kd\kd-prof.cmd opendir C:\kd\BazelSandbox.exe -W C:\kd -r C:\kd\nttest.exe @C:\kd\pdir.params -w C:\kd\out -- C:\kd\nttest.exe openloop C:\kd\files 1000 30 >> C:\kd\runall.log 2>&1
echo ===== PROFILE opennone >> C:\kd\runall.log
set BAZEL_PSEC_NO_SANDBOX=1
call C:\kd\kd-prof.cmd opennone C:\kd\BazelSandbox.exe -W C:\kd -r C:\kd\nttest.exe @C:\kd\pdir.params -w C:\kd\out -- C:\kd\nttest.exe openloop C:\kd\files 1000 30 >> C:\kd\runall.log 2>&1
set BAZEL_PSEC_NO_SANDBOX=
echo RUNALL DONE %TIME% >> C:\kd\runall.log
