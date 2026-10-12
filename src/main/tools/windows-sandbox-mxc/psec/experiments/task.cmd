@echo off
rem task.cmd <name> <script>: run <script> as mxc in the interactive console session.
schtasks /create /tn %1 /tr "%2" /sc once /st 00:00 /ru mxc /it /rl highest /f >NUL
schtasks /run /tn %1
