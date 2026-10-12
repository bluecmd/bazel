# kd-wu2.ps1: install the downloaded CU with wusa.exe (SYSTEM), log, reboot.
Start-Transcript -Path C:\kd\wu2.log -Append | Out-Null
"build before: " + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
$p = Start-Process -FilePath wusa.exe -ArgumentList 'C:\kd\dl\kb5124010.msu /quiet /norestart' -Wait -PassThru
"wusa exit: $($p.ExitCode)"
if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
  "trying dism /online /add-package"
  & dism.exe /online /add-package /packagepath:C:\kd\dl\kb5124010.msu /norestart /quiet /logpath:C:\kd\dism2.log
  "dism exit: $LASTEXITCODE"
}
"build after (registry, pre-reboot): " + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
"MSU2 DONE"
Stop-Transcript | Out-Null
shutdown /r /t 10 /f
