@echo off
rem pmenv.cmd <csv> <pid>: environment of a process's Process Start event.
powershell -NoProfile -Command "$l = Get-Content %1; $i = 0; foreach ($x in $l) { if ($x -like ('*\"%2\",\"Process Start\"*')) { $l[$i..($i+40)] | Select-String -Pattern 'BAZEL|PATH=|TMP|TEMP|Parent PID|Current directory|Environment' ; break }; $i++ }"
