@echo off
cd /d C:\mxc\psecexe\t
del /q out\a.txt 2>NUL
rem CRT-escaped form of the single argument: @copy /Y "in\a.txt" "out\" >NUL && @type "out\a.txt"
C:\mxc\psecexe\BazelSandbox.exe -D -W C:\mxc\psecexe\t -r C:\mxc\psecexe\t\in -w C:\mxc\psecexe\t\out -- cmd.exe /S /E:ON /V:ON /D /c "@copy /Y \"in\a.txt\" \"out\\\" >NUL && @type \"out\a.txt\"" 2>&1 | findstr /v /c:"  enum" /c:"  ro " /c:"  rw " /c:"ui_restr"
echo rc=%ERRORLEVEL%
