@echo off
setlocal
set T=C:\mxc\psecexe\t
mkdir %T%\in %T%\out 2>NUL
echo input-ok> %T%\in\a.txt
echo SECRET> %T%\secret.txt
del /q %T%\out\* 2>NUL
set SB=C:\mxc\psecexe\BazelSandbox.exe
echo ===== 1 read granted input, write granted output
%SB% -D -r %T%\in\a.txt -w %T%\out -- cmd /c "type %T%\in\a.txt & echo out>%T%\out\y.txt & type %T%\out\y.txt"
echo rc=%ERRORLEVEL%
echo ===== 2 read undeclared file (expect denied)
%SB% -r %T%\in\a.txt -w %T%\out -- cmd /c "type %T%\secret.txt"
echo rc=%ERRORLEVEL%
echo ===== 3 write outside (expect denied)
%SB% -r %T%\in\a.txt -w %T%\out -- cmd /c "echo leak>%T%\leak.txt"
echo rc=%ERRORLEVEL%
if exist %T%\leak.txt (echo LEAK) else (echo contained)
echo ===== 4 exit code propagation
%SB% -r %T%\in\a.txt -- cmd /c "exit 7"
echo rc=%ERRORLEVEL%
echo ===== 5 timeout
%SB% -T 2 -r %T%\in\a.txt -- cmd /c "ping -n 10 127.0.0.1 >NUL"
echo rc=%ERRORLEVEL%
echo ===== 6 env seen inside (TEMP rewrite)
%SB% -r %T%\in\a.txt -w %T%\out -- cmd /c "set TMP & set TEMP & set TMPDIR & set LOCALAPPDATA & set USERPROFILE"
echo ===== 7 no sandbox A/B
set BAZEL_PSEC_NO_SANDBOX=1
%SB% -r %T%\in\a.txt -- cmd /c "type %T%\secret.txt"
echo rc=%ERRORLEVEL%
set BAZEL_PSEC_NO_SANDBOX=
echo ===== 8 network (expect deny) then BAZEL_PSEC_NET=1
%SB% -r %T%\in\a.txt -- curl.exe -sS -m 10 -o NUL -w %%{http_code} https://api.github.com
echo rc=%ERRORLEVEL%
set BAZEL_PSEC_NET=1
%SB% -r %T%\in\a.txt -- curl.exe -sS -m 10 -o NUL -w %%{http_code} https://api.github.com
echo rc=%ERRORLEVEL%
set BAZEL_PSEC_NET=
echo ===== 9 params file
echo -r>%T%\params
echo %T%\in\a.txt>>%T%\params
%SB% @%T%\params -- cmd /c "type %T%\in\a.txt"
echo rc=%ERRORLEVEL%
