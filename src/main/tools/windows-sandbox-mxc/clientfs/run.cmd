@echo off
cd /d C:\mxc\clientfs
if not exist t mkdir t
if not exist t\in mkdir t\in
if not exist t\out mkdir t\out
echo hello-in> t\in\x.txt
echo denied-content> t\in\denied.txt
echo secret-content> t\secret.txt
rmdir t\in\missing-denied 2>NUL
echo ===== %DATE% %TIME% > log-%1.txt
clientfs_bench.exe %* >> log-%1.txt 2>&1
echo DONE rc=%ERRORLEVEL% >> log-%1.txt
