@echo args: kd-bench.cmd <label> : openloop over 1000 files x 20, under policies: none, 1 dir, 1000 files, 4000 files; times from nttest and from BazelSandbox timing
@echo off
cd /d C:\kd
set T=C:\kd\timing-%1.txt
del /q %T% 2>NUL
set BAZEL_MXC_TIMING=%T%
echo ===== no sandbox
set BAZEL_PSEC_NO_SANDBOX=1
BazelSandbox.exe -r C:\kd\nttest.exe -- C:\kd\nttest.exe openloop C:\kd\files 1000 20
set BAZEL_PSEC_NO_SANDBOX=
echo ===== directory grant (1 path)
BazelSandbox.exe -r C:\kd\nttest.exe @C:\kd\pdir.params -- C:\kd\nttest.exe openloop C:\kd\files 1000 20
echo ===== 1000 per-file grants
BazelSandbox.exe -r C:\kd\nttest.exe @C:\kd\p1000.params -- C:\kd\nttest.exe openloop C:\kd\files 1000 20
echo ===== 4000 per-file grants
BazelSandbox.exe -r C:\kd\nttest.exe @C:\kd\p4000.params -- C:\kd\nttest.exe openloop C:\kd\files 1000 20
echo ===== timing (prep spawn wait total ro rw enum code)
type %T%
