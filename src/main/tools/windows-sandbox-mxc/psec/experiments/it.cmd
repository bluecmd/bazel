@echo off
rem it.cmd <script> <log>: run <script> in this (interactive) session, output to <log>.
echo ===== IT start %DATE% %TIME% session: > %2
query session >> %2 2>&1
call %1 >> %2 2>&1
echo IT DONE rc=%ERRORLEVEL% %TIME% >> %2
