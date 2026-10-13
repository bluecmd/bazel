# Harness for `windows-psec`'s client-side filesystem policy

Not part of Bazel. `clientfs_bench.cc` links `src/main/native/windows/psec.cc`
(and Bazel's `process.cc`, `util.cc`, `file.cc`) directly; build it on Windows with
`build.cmd` after copying those sources next to it under `src\main\native\windows`.
Run it from an interactive session (session 0 kills USER32 importers inside an
environment); `run.cmd <mode> <dir>` prepares `<dir>` and writes `log-<mode>.txt`.

| mode | what |
|---|---|
| `enforce <dir>` | the same nine checks (read, write, undeclared read/write, deny, missing deny, listing, traverse) under service-side and client-side policies, 4 concurrent children |
| `create <dir> <n> <reps>` | environment creation and first launch with `n` file grants, both modes |
| `recycle <dir>` | blank environment → policy A → run → clear → policy B → run → clear → run; clear+apply vs new environment cost |
| `stress <dir>` | 16 threads × 10 recycles alternating two policies; every run must see exactly its policy |
| `storm <dir> <threads> <s> <keep>` | stock-like recycling with a refiller under load (`MANY_EXE`/`MANY_RO` for a USER32 tool) |
| `bfsleak2 <dir> <n>` | outstanding `BfsS`+`BfsG` pool allocations across apply / clear / re-apply / disjoint apply / close |
| `churn <dir> <max> <launch> [service] [every]` | create + close environments, printing the pool tags that grow |

`pooltags2.cc` prints every kernel pool tag with its outstanding allocations
and bytes (`NtQuerySystemInformation(SystemPoolTagInformation)`).
