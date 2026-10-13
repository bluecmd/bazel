# `windows-psec`: Bazel's Windows sandbox, in process, on PSEC

Branch `windows-sandbox-psec-jni`. This is the end state that
[`PLAN-BazelSandbox-cpp.md`](PLAN-BazelSandbox-cpp.md) §4a called form C: the
Bazel server itself creates Windows **process security environments** (PSEC,
`CreateProcessSecurityEnvironment` in `processmodel.dll`, Windows 11 25H2
build 26200.9550+) through JNI and attaches them to each action's
`CreateProcessW`. There is no `BazelSandbox.exe`, no extra process per action
and no MXC SDK, and environments are **pooled**: one environment per distinct
policy, shared by every action (concurrent ones included) that needs that
policy.

**Result.** A clean build of Bazel itself (`//src:bazel-dev.exe`, 6 244
actions) on the 16-thread box:

| | wall time | vs. local |
|---|---|---|
| `--spawn_strategy=local` | 2 022 s | |
| **`--spawn_strategy=windows-psec`** (default `coarse` policy) | **2 400 s** | **+18.7 %** |
| `windows-sandbox` + Rust MXC adapter, directory grants | 2 866 s | +42 % |
| `windows-sandbox` + Rust MXC adapter, per-file grants | 3 299 s | +63 % |

Means of 2/3/2/3 runs, spread under 1 %. The 4 768 sandboxed actions of a
build share ~70 environments, created in ~6 s in total; the remaining
overhead is the tools themselves running slower under the kernel's file
mediation (cl.exe +20-25 %, javac +12-19 %), not sandbox setup. With the
adapter's exact per-file policy (`precise`), in process is only ~1 % faster
than the adapter (VM: 4 400 s vs 4 455 s): the per-file cost is the OS's,
and reuse plus a coarser policy is what removes it. All four negative example
targets fail under every granularity.

## Using it

Build Bazel from this branch, then (from an interactive session, see
[Caveats](#caveats)):

```
bazel build //... ^
  --spawn_strategy=windows-psec ^
  --strategy=Genrule=local ^
  "--experimental_windows_sandbox_readonly_root=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" ^
  "--experimental_windows_sandbox_readonly_root=C:\Program Files (x86)\Windows Kits"
```

For Bazel's own tree add `--strategy=ProtocAuthenticityCheck=local` (another
bash action). The flags:

| flag | meaning |
|---|---|
| `--spawn_strategy=windows-psec` | the strategy; registered only when `processmodel.dll` offers PSEC contract 1.1, never a default |
| `--experimental_windows_psec_policy=coarse\|directories\|precise` | policy granularity, default `coarse` (see below) |
| `--experimental_windows_sandbox_readonly_root=<dir>` | repeatable; extra readable roots for toolchains outside the execroot (replaces the adapter's `BAZEL_MXC_EXTRA_RO`) |
| `--experimental_windows_psec_max_idle_environments=N` | unused environments kept for reuse, LRU (default 32) |
| `--experimental_windows_psec_client_fs` | apply the filesystem policy from the server instead of through the AppInfo service (default on; same enforcement, ~10x cheaper per path) |
| `--experimental_windows_psec_spare_environments=N` | with client-side policies: blank environments kept ready and recycled across policies (default 8; 0 = create on demand) |
| `--strategy=Genrule=local` | bash-based mnemonics cannot run in a security environment: MSYS/git-bash dies on its shared `BaseNamedObjects` directory (microsoft/mxc#1061). `cmd_bat` genrules are fine |
| `--sandbox_debug` | print each action's effective policy (and whether its environment was new or reused) |
| `requires-network` tag | the only way to get network access; everything else is denied |

### Exactly what was run on the physical box (`shibsrv`)

* **Host binary:** `C:\mxc\bin\bazel-psec.exe`, a `bazel-dev.exe` built from
  this branch's change ported to 9.3.0 (final state, including the
  directories-mode fix; the timed runs used the previous build, whose
  `coarse` code path is identical). Source: worktree `C:\mxc\psec-src` =
  9.3.0 + the runner fixes (`C:\mxc\psec\runner-fixes.diff`) +
  `C:\mxc\psec\psec-930.diff`; output root `C:\mxc\ob-psec`; rebuild with
  `C:\mxc\psec\box-psec-host.cmd`. It has no embedded JDK: set
  `JAVA_HOME=C:\mxc\jdk`.
* **Workload:** `C:\mxc\bazel-src`, untouched (still 9.3.0 + runner fixes,
  as for the reference runs), output root `C:\mxc\ob`.
* **Command** (from `C:\mxc\psec\bb-psec.cmd`, run as a scheduled task in
  Blue's interactive session; `C:\mxc\env.cmd` first):

  ```
  set JAVA_HOME=C:\mxc\jdk
  cd /d C:\mxc\bazel-src
  C:\mxc\bin\bazel-psec.exe --output_user_root=C:\mxc\ob shutdown
  C:\mxc\bin\bazel-psec.exe --output_user_root=C:\mxc\ob clean
  C:\mxc\bin\bazel-psec.exe --output_user_root=C:\mxc\ob build //src:bazel-dev.exe ^
    --jobs=16 --profile=C:\mxc\prof\<name>.profile.gz --noslim_profile ^
    --experimental_profile_include_target_label --experimental_profile_include_primary_output ^
    --execution_log_compact_file=C:\mxc\prof\<name>.spawnlog.zst --announce_rc ^
    --spawn_strategy=windows-psec --strategy=Genrule=local --strategy=ProtocAuthenticityCheck=local ^
    "--experimental_windows_sandbox_readonly_root=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" ^
    "--experimental_windows_sandbox_readonly_root=C:\Program Files (x86)\Windows Kits" ^
    --experimental_windows_psec_policy=coarse
  ```

  The local baseline is the same with `--spawn_strategy=local` instead of the
  last five flags. Logs: `C:\mxc\log\bb-PsecCoarse{1,2,3}.log`,
  `bb-PsecLocal{1,2}.log`, profiles in `C:\mxc\prof`.
* On the VM the host is also `C:\mxc\bin\bazel-psec.exe`, but there
  `C:\mxc\bazel-src` itself carries the change (`C:\mxc\psec\applied.diff`).

At the end of every command the runner reports how the pool was used, e.g.
`windows-psec (coarse): 43 actions, 4 security environments created (0.2 s,
81 paths), 39 actions reused one`.

## Design

### Native (`src/main/native/windows`)

* **`psec.h` / `psec.cc`** declare the API ourselves (it is in no SDK header:
  `CreateProcessSecurityEnvironment`, `CloseProcessSecurityEnvironment`,
  `QueryProcessSecurityEnvironmentSupport`,
  `IsProcessSecurityEnvironmentVersionSupported`, attribute
  `ProcThreadAttributeSecurityEnvironment` = 35), load `processmodel.dll` with
  `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_SYSTEM32)` once, and refuse to work
  unless contract **1.1** is available (without `fs_enumerate` nothing in the
  execroot can even be started; older builds would under-enforce, which is
  worse than failing). The ingress table is only written when support bit
  `0x8` is set.
* **FlatBuffer encoder.** The spec is the `"PSEC"` FlatBuffer of
  `ProcessSecurityEnvironment.fbs`. Bazel has no FlatBuffers in
  `third_party`, and we only ever *write* a handful of fields, so `psec.cc`
  has a ~150-line forward writer: each table is written as vtable, table, then
  the objects it references, so every `uoffset_t` points forward and the
  `soffset_t` back to its vtable, with correct alignment (the `uint64`
  `ui_restrictions` forces 8-byte table alignment). It was checked against the
  flatc 25.12.19-generated `Verifier` and reader (all fields round-trip, 3 000
  paths, non-ASCII), and `CreateProcessSecurityEnvironment` accepts it.
* **Client-side filesystem policy** (`FsApply::kClient`,
  `--experimental_windows_psec_client_fs`, default on). The AppInfo service
  spends ~1 ms per granted path, mostly in a `GetVolumePathNameW` walk over
  every ancestor and a file-backed policy-store write
  (microsoft/mxc#1468, `psec/experiments/fastfs/` on the
  `windows-sandbox-psec-exe` branch). It skips all of that when the spec has
  no paths. So the environment is created with empty path vectors, and the
  server sends the same requests to `\\.\GLOBALROOT\Device\Bfs` itself:
  `0x228014 {token, 1}` (in-memory policy entry), then per path
  `GetFileAttributesExW` and `0x228004` (kind 1 read-write, 2 read-only,
  4 deny, 6 enumerate), denied paths that do not exist retried as
  directories, `ERROR_ACCESS_DENIED` skipped when the user could not read the
  path either. `bfs.sys` keys policies on `{TokenUser, AppContainer SID}` of
  the token handle in the request. The token is taken from a `cmd.exe`
  started suspended in the new environment and killed right away (~8 ms), so
  unlike the research probe there is no private `CreateAppContainerToken`
  call, no `%LOCALAPPDATA%\Packages` diff and no lock around concurrent
  creates. Closing the environment also deletes the entry (`0x228010`).
  Network, UI and capabilities still go through the spec and the service.
* **Process creation.** `AutoAttributeList` and `WaitableProcess::Create`
  (the code every Bazel subprocess on Windows already goes through) take an
  optional environment handle and add it as a second attribute next to the
  existing `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Everything else is unchanged:
  `CREATE_SUSPENDED`, the `KILL_ON_JOB_CLOSE` job and its completion port,
  stdio through pipes or inherited file handles (handles are inherited
  regardless of the filesystem policy), timeout = terminate the job.
* **JNI.** `psec-jni.cc` backs `WindowsPsec` (support check, create/close,
  and a batch `GetFinalPathNameByHandleW` resolver);
  `WindowsProcesses.createProcessInSecurityEnvironment` is
  `createProcess` plus the handle; `WindowsSubprocessFactory.inSecurityEnvironment(handle)`
  returns a factory using it.

### Java (`src/main/java/com/google/devtools/build/lib/sandbox`)

* **`WindowsPsecSpawnRunner`** extends `AbstractSandboxSpawnRunner`. Actions
  run in the execroot itself (nothing is copied or linked); the only hook in
  shared code is `SandboxedSpawn.getSubprocessFactory()`, which
  `AbstractSandboxSpawnRunner` uses when non-null. The spawn uses the
  subprocess timeout (the process is ours, so the job is killed on timeout).
* **`WindowsPsecPolicyBuilder`** turns inputs/outputs into the four path lists
  with the rules the Rust adapter had to discover: grant symlink/junction
  targets too (resolved in native code, cached for the whole command), widen
  outputs to their parent directory, never let a read-only grant equal or
  contain a read-write one (most restrictive intent wins), enumerate the
  ancestors of every grant and of the execroot until a grant covers them,
  prune nested paths, sort, so equal policies are equal map keys. Runfiles
  trees are granted as directories, `TEST_TMPDIR`/`--sandbox_writable_path`
  through `getWritableDirs`, `--sandbox_block_path` as `fs_deny`.
* **Granularities** (`--experimental_windows_psec_policy`):
  * `precise`: one grant per declared input file (and its target). Exactly
    the adapter's policy. Policies are practically unique per action, so this
    is one fresh environment per action; kept to demonstrate per-file
    enforcement.
  * `directories`: the directory of each input file instead (unless that
    directory holds an output, then the file), outputs through their
    directories and the temp root instead of the per-action temp directory.
    Shared between actions with the same set of directories (a third of the
    actions in Bazel's own build).
  * `coarse` (default): per input, the execroot entry it lives in, resolved:
    `<workspace>\<top-level dir>` for sources (a file at the top of the
    workspace is granted alone), the whole `<output_base>\external` for
    external repositories (repositories that live elsewhere, e.g.
    `bazel_tools` in the install base, by their own root), the readonly roots;
    the whole output tree and the temp root are writable. Bazel's own build
    needs ~70 distinct policies, most of the variety coming from the
    `<execroot>\external\<repo>` junction paths, which are granted next to
    their targets as the adapter does (`--host_jvm_args=-Dbazel.windows_psec.no_link_grants=true`
    drops the link paths; unmeasured).
* **`WindowsPsecEnvironmentPool`**: `Spec` → environment, shared, reference
  counted. The first action with a new policy creates the environment, others
  arriving meanwhile wait for it; idle environments stay for reuse (LRU,
  `--experimental_windows_psec_max_idle_environments`) and are only closed
  when nobody uses them, at the latest at the end of the command.
  With client-side policies an environment is no longer tied to one policy:
  the pool also keeps a **stock of blank environments** (no filesystem
  access), filled up to `--experimental_windows_psec_spare_environments` by a
  background thread that starts with the first sandboxed action. A new policy
  takes a blank environment from the stock and only applies its paths;
  evicted environments are cleared (`0x228010` + `0x228014`) and go back into
  the stock instead of being closed. Clearing and re-applying a small policy
  takes ~1.4 ms against ~42 ms for a new environment (VM), and the old
  policy's paths are denied afterwards (checked with 16 threads × 10 recycles,
  alternating policies). A recycled environment keeps its
  `...\Packages\sandbox.{guid}\AC\Temp`, so leftovers of an earlier action
  in that directory are visible to a later one, as they already are for
  actions sharing an environment. **Starvation** is reported at the end of
  every command: how many policies were set up on a ready environment
  (created ahead or recycled), how many found the stock empty and created one
  inline (and how long that took), and how long actions waited for an
  environment in total and at most; the profile has `psec.createBlank` and
  `psec.applyPolicy` spans.
* **Environment block.** The action's environment is passed verbatim, plus
  `TMP`/`TEMP`/`TMPDIR` = the action's own temp dir `<output_base>\psec\<n>`
  (Windows rewrites `TEMP`/`TMP` inside the environment to the shared
  `...\Packages\sandbox.{guid}\AC\Temp`, `TMPDIR` survives, and Python's
  `tempfile` prefers it), and `USERPROFILE`/`LOCALAPPDATA` if missing
  (`CreateProcessW` refuses without them). The temp root is short on purpose,
  see [Caveats](#caveats).
* **UI**: `disallow_win32k_system_calls = false`, `ui_restrictions = 0x3DE`
  (what MXC computes for `ui.isolation = desktop`: USER32 works; clipboard,
  desktop switching, logoff, system settings, IME and input injection are
  blocked).
* **Network**: egress and ingress deny, `host_loopback` deny; an action
  tagged `requires-network` (or a build with `--test_arg=--wrapper_script_flag=--debug`,
  as on Linux) gets egress allow plus the `internetClient` capability.
  `--sandbox_default_allow_network` is deliberately **not** honoured: its
  default is `true`, which would make the policy allow-by-default.

## Measurements

All on Windows 11 25H2 26200.9550 (`processmodel.dll` 10.0.26100.9549, PSEC
contract 1.1, support flags `0xF`).

### The primitive, from native code (VM, 8 vCPU)

A small harness over `psec.cc` and Bazel's own `WaitableProcess` (the exact
code path the runner uses), mean of 10-20 launches after a warm-up, policy =
the test directory plus Visual Studio and the Windows Kits as two directory
grants:

| | no environment | reused environment | fresh environment (create + launch) | create alone |
|---|---|---|---|---|
| `cmd /c exit 0` | 42.6 ms | 63.0 ms | 95.4 ms | 33.3 ms |
| `cl /c` of an empty `main` | 453 ms | 637 ms | 670 ms | 36.6 ms |

* Attaching an existing environment costs ~20 ms per process; creating one
  ~33 ms plus ~1 ms per path (the plan's probe numbers hold in process).
* **One environment serves concurrent processes.** 16 `cmd` children started
  at once from 16 threads with the same handle all ran, all could read the
  granted input and write the granted output, all were denied the undeclared
  file and the write outside, and all saw the same
  `...\Packages\sandbox.{guid}\AC\Temp`. That is what makes sharing a
  pool entry between concurrent actions (rather than one entry per in-flight
  action) possible.
* Reuse does not make the contained tool faster: cl.exe is ~185 ms (40 %)
  slower inside an environment whether it is fresh or reused. That is the
  filesystem mediation, paid per file access.
* Nor does policy size: the same cl.exe run in a reused environment took
  619/630 ms with the small policy and 624/622 ms with 2 000 extra read-only
  paths in it (two alternating rounds of 10). Big policies cost at `Create`
  (1.6 s for those 2 000 paths), not per access.

### The example workspace (`example/run-psec.cmd`, VM and box)

All three granularities: `//...` (genrule, cl.exe, link.exe; 43 sandboxed
actions) builds and `hello.exe` runs; the four negative targets fail exactly
as under the Rust adapter, and all four succeed with `--spawn_strategy=local`:

| action | `precise` | `directories` | `coarse` | `local` |
|---|---|---|---|---|
| read an undeclared source file (`secret.txt`) | Access is denied | Access is denied | Access is denied | ok |
| write `C:\Users\Public\bazel-mxc-leak.txt` | Access is denied, no file | Access is denied, no file | Access is denied, no file | ok |
| launch an undeclared tool (`tools\whoami.exe`) | Access is denied | Access is denied | Access is denied | ok |
| `curl https://api.github.com` | Could not resolve host | Could not resolve host | Could not resolve host | ok |
| environments for `//...` (43 actions) | 43 | 4 (43 before the temp-root fix) | 4 | |

The same results on the box with the final binary. 40 trivial `cmd_bat`
genrules after `bazel clean`, warm server (cf. the adapter on the VM: 2.5 s
local vs 10.4 s at `--jobs=1`, i.e. ~200 ms per action):

| | local | `precise` | `directories` | `coarse` |
|---|---|---|---|---|
| VM, `--jobs=1` | 2.69 s | 5.79 s | 5.76 s ¹ | 3.12 s |
| VM, `--jobs=8` | 1.07 s | 1.62 s | 1.88 s ¹ | 1.44 s |
| box, `--jobs=1` | 1.99 s | 4.23 s | 2.47 s | 2.42 s |
| box, `--jobs=8` | 0.63 s | 1.17 s | 0.72 s | 0.74 s |
| environments created | | 40 | 1 (40 ¹) | 1 |

¹ before the temp-root fix, when `directories` could not share environments.

So a sequential trivial action costs ~78 ms (VM) / ~60 ms (box) under
`coarse` against ~67 / ~50 ms locally and ~145 / ~105 ms with a fresh
environment per action.

### Building Bazel: the VM

8 vCPU, 32 GB, same tree, `--jobs=8`, same protocol. Here the workload tree
carried the change itself (6 250 actions instead of 6 244). The adapter rows
are the README's runs on this VM.

| configuration | wall time, s | vs. local | environments created | `Create` time, total |
|---|---|---|---|---|
| local, same host (P3) | 2831 | | | |
| local, patched 9.3.0 host (earlier) | 2818 | | | |
| **`windows-psec`, `coarse` (P2)** | **3270** | **+15.5 %** | 74 | 5.3 s |
| `windows-psec`, `coarse`, first run (P1, one action failed, see Caveats) | 3213 | | 71 | 5.6 s |
| `windows-psec`, `directories`, before the temp-dir fix (P4) | 3604 | +27 % | 4 774 (no reuse) | 1 296 s |
| `windows-psec`, `directories` (P6, after the fix) | 3521 | +24 % | 3 153 (1 621 reuses) | 904 s |
| `windows-psec`, `precise` (P5) | 4400 | +55 % | 4 774 (no reuse) | 8 191 s (2.31 M paths) |
| `windows-sandbox` + adapter, directory grants (earlier) | 3853 | +37 % | one per action | |
| `windows-sandbox` + adapter, per-file grants (earlier) | 4455 | +58 % | one per action | |
| default strategies (Javac workers), for scale | 1289 | -54 % | | |

Per action, local (P3) vs `coarse` (P2): CppCompile 5.75 s vs 7.18 s
(+25 %), Javac 10.64 s vs 11.90 s (+12 %), CppLink 1.21 s vs 2.30 s,
Turbine/StampJarManifest/Genrule unchanged. Summed over actions and divided by
the 8 jobs, the CppCompile and Javac deltas alone are ~440 s, i.e. the whole
wall-time difference; setup is no longer visible.

### Building Bazel: the physical box (headline)

Same machine and protocol as the README's adapter numbers: Windows 11
Enterprise 25H2 26200.9550, 16-thread Xeon D class, 64 GB; clean
`bazel build //src:bazel-dev.exe` of the 9.3.0 tree (with the
`windows-sandbox` runner fixes, unchanged from the reference runs, 6 244
actions), `--jobs=16`, fresh server and `bazel clean` before every run, JSON
profile and compact execution log written, `Genrule` and
`ProtocAuthenticityCheck` local in all sandboxed configurations. Host for the
`windows-psec` and "local, same host" rows: `bazel-dev.exe` built from this
change (on 9.3.0); the other rows used the patched 9.3.0 host of the
earlier runs. Runs in the order listed.

| configuration | wall time, s | mean | vs. local (same host) |
|---|---|---|---|
| **`windows-psec`, `coarse`** | 2403, 2395, 2402 | **2400** | **+18.7 %** |
| local, same host (interleaved with the above) | 2028, 2015 | 2022 | |
| local, patched 9.3.0 host (earlier) | 2103, 2074, 2034 | 2070 | |
| `windows-sandbox` + Rust adapter, per-file grants (earlier) | 3290, 3305, 3303 | 3299 | +63 % |
| `windows-sandbox` + Rust adapter, directory grants (earlier) | 2858, 2875 | 2866 | +42 % |

Per action (profile "action processing" spans, mean over a run):

| mnemonic | count | local | adapter, per-file | adapter, dir grants | `windows-psec` `coarse` |
|---|---|---|---|---|---|
| CppCompile | 1569 | 7.68 s | 15.63 s | 11.93 s | 9.25 s |
| Javac | 1023 | 17.06 s | 22.40 s | 21.58 s | 20.23 s |
| Turbine | 1010 | 0.88 s | 1.58 s | 1.39 s | 0.79 s |
| StampJarManifest | 100 | 1.27 s | 4.10 s | 3.86 s | 1.40 s |
| CppLink | 28 | 1.45 s | 3.59 s | 3.34 s | 2.40 s |
| Genrule (local in all) | 137 | 1.83 s | 2.19 s | 2.03 s | 1.81 s |

`coarse` on the box: 4 768 sandboxed actions in 70-72 environments per build,
6.3 s of `CreateProcessSecurityEnvironment` in total (median 88 ms, under
16-way load); acquiring an environment for an action: median 0.03 ms, p99
80 ms (waiting for one being created); building the policy: median 4 ms, p99
49 ms, 33 s in total.

### Choosing the default granularity

All three granularities make the four negative example targets fail, so the
choice is about speed and about how much an undeclared access within the
granted roots is still caught:

| granularity | VM wall time | environments per build | per-action mean, CppCompile / Javac (VM) |
|---|---|---|---|
| `precise` | 4400 s (+55 %) | 4 774 | 10.84 s / 14.51 s |
| `directories` | 3521 s (+24 %) | 3 153 | 7.73 s / 13.09 s |
| `coarse` | **3270 s (+15.5 %)** | 74 | 7.18 s / 11.90 s |
| local | 2831 s | | 5.75 s / 10.64 s |

`coarse` is the default. Per-action times include waiting for one's own
environment, but even net of that the actions run slower the more
environments are being created around them (CppCompile is ~9.1 s in `precise`
after subtracting the mean 1.7 s create, vs 7.2 s in `coarse`), although
neither policy size nor freshness of the environment slows a tool by itself
(previous section). The likely explanation, not verified with a kernel trace,
is that the stream of `CreateProcessSecurityEnvironment` calls (one
`bfs.sys` policy IOCTL per path, 2.3 million of them in a `precise` build)
contends with the mediation of the running actions' file accesses. Fewer,
shared environments avoid both costs.

## What `coarse` gives up

`coarse` enforces the same *kinds* of boundary as `precise` (filesystem
outside the granted roots, writes outside the output tree, network), at a
coarser grain. Concretely, an action can:

* **read any file under a top-level source directory it has at least one
  declared input in** (e.g. all of `src\` if it reads one file there), not
  just its declared inputs. Undeclared reads across top-level directories and
  of top-level files (the `undeclared_read` example reads `secret.txt` at the
  workspace root) still fail.
* **read every external repository** under `<output_base>\external` as soon
  as it reads one.
* **write anywhere in the output tree** (`bazel-out`), i.e. clobber other
  actions' outputs, and read them. Writes outside it (the source tree, the
  user profile, `C:\Users\Public` in `undeclared_write`) still fail.
* **see other concurrent actions' temp files** (one temp root, and the
  `AC\Temp` Windows redirects `TEMP` to is per environment, hence shared by
  all actions using it).
* run **any executable it can read**, e.g. tools in a top-level directory it
  reads, not only declared tool inputs (`undeclared_tool` still fails: it has
  no input under `tools\`).

So `coarse` catches the gross mistakes (reaching into the user profile, the
rest of the disk, another top-level tree, the network) but not a missing
`deps` edge inside one top-level directory; it is a hardening mode, not a
hermeticity checker. `directories` narrows reads to the directories that hold
declared inputs (siblings in those directories stay readable) and outputs to
their directories; `precise` is per file, like the Linux sandbox's
read-only bind mounts.

## Caveats

* **Interactive session required.** In session 0 (ssh, services) every
  contained process that imports USER32 (cl.exe, link.exe, java.exe, ...) dies
  with `STATUS_DLL_INIT_FAILED` (0xC0000142) whatever the UI policy says
  (microsoft/mxc#1465). Run Bazel from a console/RDP session (CI: autologon +
  a scheduled task with `/it`). The Bazel *server* inherits the session of the
  client that started it, so `bazel shutdown` after switching.
* **Undocumented API.** We declare the PSEC signatures, the attribute number
  and the FlatBuffer layout ourselves (from MXC's FFI, the schema MXC vendors
  and the `processmodel.pdb` symbols). The code gates on
  `IsProcessSecurityEnvironmentVersionSupported(1)` reporting minor >= 1 and
  only registers the strategy then; a future build that changes the ABI
  without bumping the contract version would break it, in process. A crash in
  this code is a crash of the Bazel server, not of a helper.
* **No bash.** MSYS/git-bash cannot start inside a security environment
  (microsoft/mxc#1061): `genrule(cmd=...)`, `sh_binary`, `sh_test` and other
  `BAZEL_SH` users need `--strategy=<Mnemonic>=local`. Bazel's own build needs
  `Genrule` and `ProtocAuthenticityCheck`.
* **No symlink/junction creation inside the environment** (by design, MXC
  issue 462), so actions that build runfiles symlink trees themselves fail;
  Bazel creates the execroot forest outside, so normal builds are fine.
* **TEMP is redirected.** Windows points `TEMP`/`TMP` (and `LOCALAPPDATA`) of
  a contained process at `...\Packages\sandbox.{guid}\AC\Temp`, whatever
  Bazel passes; directories created there with an owner-only DACL are
  unusable by the creator. `TMPDIR` is set to the action's own directory,
  which Python's `tempfile` prefers. That directory is
  `<output_base>\psec\<n>` and must stay short: zipped `py_binary` tools
  extract their runfiles there and the deepest paths otherwise exceed
  MAX_PATH (the first full build hit this in rules_pkg's `build_tar`).
* **Network policy** is all or nothing per action (`requires-network`); no
  per-host allow lists, no proxy, and `--sandbox_default_allow_network` is
  ignored on purpose.
* **Toolchains** outside the execroot must be listed with
  `--experimental_windows_sandbox_readonly_root` (Visual Studio, Windows Kits;
  a local JDK, Python or node if not fetched as external repositories).
* **Not a default and not for workers.** `windows-psec` only applies to
  spawns run by it; persistent workers (the default for Javac) run unsandboxed
  through the worker strategy, and building with `--spawn_strategy=windows-psec`
  disables them, which costs far more than the sandbox (see the measurements).
  Tests (`bazel test`) are untested.
* **Unresolved symlink inputs** (`ctx.actions.symlink` with
  `target_path`) are rejected, as in the old `windows-sandbox` runner.
* **Tests.** `WindowsPsecPolicyBuilderTest` and `WindowsPsecEnvironmentPoolTest`
  (13 cases, platform independent) are in `SmallTests`. They were run with
  plain JUnit outside Bazel, because Bazel's own test targets could not be
  built on the Linux development host (its C++ toolchain cannot link there).
  The JNI and the runner are exercised only by the example and the full
  builds above; there is no automated Windows integration test yet.
* **Ported to 9.3.0 for the measurements.** The branch is on Bazel master;
  the VM and the box build a 9.3.0 tree, so the measured host is the same
  change ported to 9.3.0 (differences: options as public fields instead of
  abstract getters, `getInputMapping(PathFragment, boolean)`, BUILD labels).
  On the VM the workload tree carried the change too (one extra action); on
  the box the host was built in a separate worktree and the workload tree is
  byte-identical to the earlier reference runs.

## Files

| file | what |
|---|---|
| `src/main/native/windows/psec.h`, `psec.cc` | API declarations, loader, FlatBuffer encoder, create/close |
| `src/main/native/windows/psec-jni.cc` | JNI for `WindowsPsec` |
| `src/main/native/windows/util.*`, `process.*`, `processes-jni.cc` | security-environment attribute on the existing process creation path |
| `.../lib/windows/WindowsPsec.java`, `WindowsProcesses.java` | Java side of the JNI |
| `.../lib/shell/WindowsSubprocessFactory.java` | `inSecurityEnvironment(handle)` |
| `.../lib/sandbox/SandboxedSpawn.java`, `AbstractSandboxSpawnRunner.java` | `getSubprocessFactory()` hook |
| `.../lib/sandbox/WindowsPsec*.java` | runner, spawn, strategy, policy builder, pool |
| `.../lib/sandbox/SandboxOptions.java`, `SandboxModule.java` | flags, registration, pool shutdown at the end of a command |
| `src/test/.../sandbox/WindowsPsec*Test.java` | policy builder and pool tests (platform independent) |
| `example/run-psec.cmd` | the example under all three granularities |
