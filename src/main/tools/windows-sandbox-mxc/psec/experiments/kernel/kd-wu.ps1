# kd-wu.ps1: install KB5124010 (26200.9550 preview CU) offline-style, then reboot. Runs as SYSTEM.
$Url = 'https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/518df5fb-59fb-43d7-a44f-990e150b948a/public/windows11.0-kb5124010-x64_95a6272121df38221bfafc90b50baa8ec3e5294e.msu'
Start-Transcript -Path C:\kd\wu.log -Append | Out-Null
try {
  New-Item -ItemType Directory -Force C:\kd\dl | Out-Null
  $msu = 'C:\kd\dl\kb5124010.msu'
  if (-not (Test-Path $msu)) { "downloading"; & curl.exe -sS -L -o $msu $Url; "download exit $LASTEXITCODE" }
  "msu size: {0} MB" -f [int]((Get-Item $msu).Length/1MB)
  "build before: " + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
  $t = Measure-Command { $r = Add-WindowsPackage -Online -PackagePath $msu -NoRestart -LogPath C:\kd\dism.log }
  "Add-WindowsPackage: restartNeeded=$($r.RestartNeeded) in $([int]$t.TotalSeconds)s"
  "build after: " + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
} catch { "ERROR: $_" }
"MSU DONE"
Stop-Transcript | Out-Null
shutdown /r /t 10 /f
