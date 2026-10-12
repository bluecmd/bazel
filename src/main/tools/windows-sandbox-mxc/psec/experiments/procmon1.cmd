@echo off
setlocal
set T=C:\mxc\psecexe\t
set SB=C:\mxc\psecexe\BazelSandbox.exe
set GIT=C:\Program Files\Git
set PM=C:\mxc\psecexe\tools\Procmon64.exe
set KEY=msys-2.0S5-1888ae32e00d56aa
start /b C:\mxc\psecexe\bnodir.exe hold \BaseNamedObjects\%KEY% 120
start /b C:\mxc\psecexe\bnodir.exe hold \Sessions\1\BaseNamedObjects\%KEY% 120
del /q C:\mxc\psecexe\bash.pml C:\mxc\psecexe\bash.csv 2>NUL
start "" %PM% /AcceptEula /Quiet /Minimized /BackingFile C:\mxc\psecexe\bash.pml
timeout /t 6 >NUL
echo ===== bash inside PSEC under procmon
%SB% -r "%GIT%" -r %T%\in -w %T%\out -- "%GIT%\usr\bin\bash.exe" -c "echo hi from bash"
echo rc=%ERRORLEVEL%
%PM% /Terminate
timeout /t 5 >NUL
%PM% /AcceptEula /Quiet /OpenLog C:\mxc\psecexe\bash.pml /SaveAs C:\mxc\psecexe\bash.csv
timeout /t 5 >NUL
dir C:\mxc\psecexe\bash.*
findstr /i /c:"bash.exe" C:\mxc\psecexe\bash.csv | findstr /v /c:"SUCCESS" | findstr /v /c:"FAST IO DISALLOWED" | findstr /v /c:"NO MORE FILES" | findstr /v /c:"END OF FILE" | findstr /v /c:"BUFFER OVERFLOW" | findstr /v /c:"REPARSE"
taskkill /f /im bnodir.exe >NUL 2>&1
