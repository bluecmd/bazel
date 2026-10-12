$sid = (whoami /user /fo csv | ConvertFrom-Csv).SID
"user: $sid"
$ac = [System.Security.Principal.WindowsIdentity]::GetCurrent()
"appcontainer sid: " + ($ac.Groups | Where-Object { $_.Value -like 'S-1-15-2-*' } | ForEach-Object { $_.Value }) -join ','
$sess = (Get-Process -Id $PID).SessionId
"session: $sess"
$pk = whoami /all | Select-String -Pattern 'S-1-15-2-' | ForEach-Object { $_.Line.Trim() }
"package sids: $pk"
$acsid = ($ac.Groups | Where-Object { $_.Value -like 'S-1-15-2-*' } | Select-Object -First 1).Value
foreach ($n in @("psectest-$PID", "LOCAL\psectest-$PID", "Sessions\$sess\AppContainerNamedObjects\$acsid\psectest-$PID", "msys-1888ae32e00d56aa-$PID")) {
  try { $p = New-Object System.IO.Pipes.NamedPipeServerStream($n, [System.IO.Pipes.PipeDirection]::InOut, 1); "OK   \\.\pipe\$n"; $p.Dispose() }
  catch { "FAIL \\.\pipe\$n : " + $_.Exception.InnerException.Message + $_.Exception.Message }
}
foreach ($n in @("Global\psecevt-$PID", "psecevt-$PID")) {
  try { $e = New-Object System.Threading.EventWaitHandle($false, 'ManualReset', $n); "OK   event $n"; $e.Dispose() } catch { "FAIL event $n : " + $_.Exception.Message }
}
