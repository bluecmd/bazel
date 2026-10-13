# Empty-grants baseline (task-2), psec2, pristine processmodel.dll 26100.9549, 2026-10-12

BAZEL_MXC_TIMING columns: prep(create+spec) spawn wait total ro rw enum code.
Runs via C:\kd\fastfs-base.cmd; child = nttest openloop 1000 files x5 (or cmd /c exit 0 for the 0-path case).

| case | prep/create ms | spawn ms | wait ms | total ms | rc | note |
|---|---|---|---|---|---|---|
| 0 paths, `cmd /c exit 0` | 37 | 19 | 46 | 103 | 0 | spawn+run works with zero grants |
| 1 path (-r nttest.exe) | 38 | 12 | 785 | 835 | 0 | openloop fails=5000 (files not granted, expected) |
| 1 dir grant | 36 | 12 | 1145 | 1192 | 0 | fails=0 |
| 100 files | 112 | 11 | 801 | 924 | 0 | fails=4500 (only granted files pass) |
| 300 files | 283 | 12 | 868 | 1164 | 0 | fails=3500 |
| 1000 files | 865 | 12 | 1131 | 2008 | 0 | fails=0 |
| 4000 files | 4116 | 12 | 1158 | 5286 | 0 | fails=0 |

Conclusions:
- Create with zero fs paths succeeds (~37 ms: spec parse + AppContainer profile + token + registry), child spawns and runs.
- The service-side cost is ~1.03 ms per file path (4000 paths: 4116 ms create), consistent with GAPS §4.9.4.
- With empty fs vectors the service skips ApplyFilesystemPolicy entirely (SbepCreateSandbox guards it on
  "any vector non-empty"); it still parses/validates the spec, creates the AppContainer profile
  (CreateAppContainerProfile), applies capabilities and network policies, and registers the SandboxInstance.
- Reference from the previous session (timing-base-before.txt, same dll build, older image):
  1000 files 829 ms, 4000 files 3247 ms — same order of magnitude.
