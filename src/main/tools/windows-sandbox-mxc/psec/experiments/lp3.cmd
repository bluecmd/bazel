@echo off
set P=C:\mxc\ob\zimdgeq3\execroot\_main\external\rules_jvm_external++maven+com_google_guava_listenablefuture_9999_0_empty_to_avoid_conflict_with_guava\file\v1\com\google\guava\listenablefuture\9999.0-empty-to-avoid-conflict-with-guava\listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
set T=C:\mxc\ob\cache\repos\v1\contents\9da36f961b647e04057151ecf9288ae3f35819033b08c50e2c153c1131c07756\bace8d81-c2ef-4fa4-891b-09cc848e328f\file\v1\com\google\guava\listenablefuture\9999.0-empty-to-avoid-conflict-with-guava\listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar
set NT=C:\mxc\psecexe\tools\busyboxlp.exe
set SB=C:\mxc\psecexe\BazelSandbox3.exe -D -r %NT%
echo ===== A: grant the long file path (link) and its target, as the action did
%SB% -r "%P%" -r "%T%" -- %NT% sh -c "ls -l '%P:\=/%'" 2>&1 | findstr /v /c:"  enum"
echo ===== B: grant with \\?\ prefix
%SB% -r "\\?\%P%" -r "\\?\%T%" -- %NT% sh -c "ls -l '%P:\=/%'" 2>&1 | findstr /v /c:"  enum"
echo ===== C: grant the parent directories (what directory-grant mode would do)
%SB% -r "%P%\.." -r "%T%\.." -- %NT% sh -c "ls -l '%P:\=/%'" 2>&1 | findstr /v /c:"  enum"
echo ===== D: BAZEL_MXC_DIR_GRANTS=1 with the long file paths
set BAZEL_MXC_DIR_GRANTS=1
%SB% -r "%P%" -r "%T%" -- %NT% sh -c "ls -l '%P:\=/%'" 2>&1 | findstr /v /c:"  enum"
