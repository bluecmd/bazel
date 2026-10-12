@echo off
set P=C:/mxc/ob/zimdgeq3/execroot/_main/external/rules_jvm_external++maven+com_google_guava_listenablefuture_9999_0_empty_to_avoid_conflict_with_guava/file/v1/com/google/guava/listenablefuture/9999.0-empty-to-avoid-conflict-with-guava/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
set SB=C:\mxc\psecexe\BazelSandbox.exe -W C:\mxc\ob\zimdgeq3\execroot\_main -r C:\mxc\psecexe\tools -r "C:\mxc\ob\zimdgeq3\execroot\_main\external\rules_jvm_external++maven+com_google_guava_listenablefuture_9999_0_empty_to_avoid_conflict_with_guava" -r C:\mxc\psecexe\nttest.exe -w C:\mxc\psecexe\t\out --
echo ===== long path inside PSEC, busyboxlp (absolute)
%SB% C:\mxc\psecexe\tools\busyboxlp.exe sh -c "ls -l '%P%'"
echo rc=%ERRORLEVEL%
echo ===== relative path from the execroot, as the genrule does
%SB% C:\mxc\psecexe\tools\bash.exe -c "cp external/rules_jvm_external++maven+com_google_guava_listenablefuture_9999_0_empty_to_avoid_conflict_with_guava/file/v1/com/google/guava/listenablefuture/9999.0-empty-to-avoid-conflict-with-guava/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar C:/mxc/psecexe/t/out/lp2.jar && ls -l C:/mxc/psecexe/t/out/lp2.jar"
echo rc=%ERRORLEVEL%
echo ===== same, no sandbox
set BAZEL_PSEC_NO_SANDBOX=1
%SB% C:\mxc\psecexe\tools\bash.exe -c "cp external/rules_jvm_external++maven+com_google_guava_listenablefuture_9999_0_empty_to_avoid_conflict_with_guava/file/v1/com/google/guava/listenablefuture/9999.0-empty-to-avoid-conflict-with-guava/listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar C:/mxc/psecexe/t/out/lp3.jar && ls -l C:/mxc/psecexe/t/out/lp3.jar"
echo rc=%ERRORLEVEL%
set BAZEL_PSEC_NO_SANDBOX=
echo ===== nttest: open the long path inside PSEC
%SB% C:\mxc\psecexe\nttest.exe open "%P:/=\%" r
