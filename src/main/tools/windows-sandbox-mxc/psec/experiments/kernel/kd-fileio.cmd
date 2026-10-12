@echo off
rem kd-fileio.cmd: FileIO trace of 1000 x 5 opens, with a directory grant and without a sandbox; counts of FileIO Create events per process.
cd /d C:\kd
echo ===== FILEIO start %TIME% > C:\kd\fileio.log
for %%c in (sb none) do (
  del /q C:\kd\fio-%%c.etl C:\kd\fio-%%c.csv 2>NUL
  wpr -start FileIO -filemode
  if "%%c"=="none" set BAZEL_PSEC_NO_SANDBOX=1
  C:\kd\BazelSandbox.exe -W C:\kd -r C:\kd\nttest.exe @C:\kd\pdir.params -w C:\kd\out -- C:\kd\nttest.exe openloop C:\kd\files 1000 5 >> C:\kd\fileio.log 2>&1
  set BAZEL_PSEC_NO_SANDBOX=
  wpr -stop C:\kd\fio-%%c.etl
  tracerpt C:\kd\fio-%%c.etl -o C:\kd\fio-%%c.csv -of CSV -y >NUL
  echo ===== %%c: FileIO events by type and process >> C:\kd\fileio.log
  powershell -NoProfile -Command "$r = Import-Csv C:\kd\fio-%%c.csv; $r | Where-Object { $_.'Event Name'.Trim() -eq 'FileIo' } | Group-Object { $_.Type.Trim() + ' pid=' + $_.PID.Trim() } | Sort-Object Count -Descending | Select-Object -First 14 | ForEach-Object { '{0,8} {1}' -f $_.Count, $_.Name }; $r | Where-Object { $_.'Event Name'.Trim() -eq 'Process' } | ForEach-Object { $_.'User Data' } | Select-String -Pattern 'nttest|BazelSandbox|svchost.*Appinfo|System' | ForEach-Object { $_.Line.Substring(0, [Math]::Min(120, $_.Line.Length)) }" >> C:\kd\fileio.log 2>&1
)
echo FILEIO DONE >> C:\kd\fileio.log
