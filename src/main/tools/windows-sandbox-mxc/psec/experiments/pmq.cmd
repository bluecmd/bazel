@echo off
rem pmq.cmd <csv> <pid>: the interesting events of one process in a Process Monitor csv.
findstr /c:"\"%2\"" %1 | findstr /v /c:"RegOpenKey" /c:"RegQueryValue" /c:"RegCloseKey" /c:"RegQueryKey" /c:"CreateFileMapping" /c:"QueryNameInformationFile" /c:"QueryBasicInformationFile" /c:"CloseFile" /c:"Load Image" /c:"QueryStandardInformationFile" /c:"ReadFile" /c:"FAST IO" /c:"QueryRemoteProtocol" /c:"Thread Create" /c:"QuerySecurityFile" /c:"QueryAttributeTag" /c:"QueryNetworkOpenInformationFile" > C:\mxc\psecexe\pmq.out
powershell -NoProfile -Command "Get-Content C:\mxc\psecexe\pmq.out | Select-Object -Last 40"
