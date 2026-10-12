# windows-sandbox backed by Microsoft Execution Containers (experimental)

Bazel has had a `windows-sandbox` spawn strategy since 1.0: with
`--experimental_use_windows_sandbox=yes` the `WindowsSandboxedSpawnRunner`
hands every action to an external `BazelSandbox.exe`, passing the declared
inputs as read-only paths, the outputs and `TMP` as writable paths and the
command line after `--` (see `WindowsSandboxUtil.java`). No such binary was ever
shipped; the GSoC 2019 prototype wrapped BuildXL's Detours sandbox.

This directory contains an adapter that implements that contract on top of
[Microsoft Execution Containers](https://github.com/microsoft/mxc) (MXC, announced
at Build 2026). MXC's `processcontainer` mode uses the kernel-enforced process
security environment (`CreateProcessSecurityEnvironment`, "PSEC") that ships in
Windows 11 25H2: a deny-by-default path policy applied to the whole process tree,
network egress/ingress policy, and no DLL injection or hooks. That is a much
better fit for Bazel than Detours was: the policy is declared up front from the
action's inputs and outputs, exactly the data Bazel already passes.

**Status: a real `bazel build //...` (genrule, `cl.exe`, `link.exe`) runs
sandboxed end to end, undeclared reads/writes/tool launches/network are denied,
and no change to Bazel itself was needed.** It is an experiment, not a proposal
to merge as is. Measured on Bazel 9.1.1 and 9.3.0, MXC 1.0.0, Windows 11 25H2
build 26200.9550.

The adapter is a small Rust program linking the [`mxc-sdk`](https://crates.io/crates/mxc-sdk)
crate, so the process security environment is created in-process: Bazel ->
`BazelSandbox.exe` -> action, with no `wxc-exec.exe` hop. (The first version
was a C shim around `wxc-exec.exe`; the exe hop cost about 25 ms per action
and nothing else, since `wxc-exec` is itself a thin CLI over the same crate.)

> **In-process successor:** [`PSEC-JNI.md`](PSEC-JNI.md) describes the
> `windows-psec` strategy on the `windows-sandbox-psec-jni` branch: the Bazel
> server creates the process security environments itself through JNI, pools
> them by policy, and needs neither this adapter nor the MXC SDK.

## Contents

| file | what |
|---|---|
| `src/main.rs`, `Cargo.toml` | The adapter. `cargo build --release` with a stable MSVC toolchain produces `target\release\BazelSandbox.exe`. |
| `example/` | Minimal workspace: positive build, four negative targets that must fail under the sandbox, 40 trivial genrules for overhead measurement. `example/run.cmd` runs all of it. |

## Requirements

- Windows 11 25H2 **26200.9550 or later** (KB5124010, September 2026 *preview*
  cumulative update, or anything newer). This is the first build whose
  `processmodel.dll` implements PSEC contract 1.1 with `enumeratePaths`; without
  it a contained process cannot traverse the directories above its grants, so
  nothing in the execroot can even be launched. On 26200.9457 (the September
  security CU) MXC selects the native tier but cannot run a single real action.
  On older builds MXC falls back to a deprecated AppContainer+DACL tier where
  per-file read grants do not take effect. Windows Update may not offer the
  preview CU; the MSU from the Microsoft Update Catalog installs with
  `Add-WindowsPackage -Online`.
- Nothing from MXC needs to be installed: the adapter links `mxc-sdk` 1.0.0
  statically. If you have `wxc-exec.exe` around, `wxc-exec.exe --probe` should
  report tier `base-container` and `baseContainerSupportsEnumeratePaths: true`.
- Bazel must run from an **interactive session** (console or RDP). From an
  SSH shell (session 0, network logon token, no interactive window station)
  every tool that imports `USER32.dll` (cl.exe, node, PowerShell, whoami, ...)
  dies inside the container with `STATUS_DLL_INIT_FAILED` (0xC0000142),
  whatever the UI policy says. This cost a day; it looks like an MXC bug and
  is not one.

## Usage

```
cargo build --release
bazel build //... ^
  --experimental_use_windows_sandbox=yes ^
  --experimental_windows_sandbox_path=C:\path\to\target\release\BazelSandbox.exe ^
  --spawn_strategy=windows-sandbox ^
  "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits"
```

Bazel scrubs the action environment down to `PATH`/`TEMP`/`TMP`, so the adapter's
knobs have to come in through `--action_env`:

| variable | effect |
|---|---|
| `BAZEL_MXC_EXTRA_RO=<p>;<p>` | extra read-only roots for toolchains Bazel does not declare as inputs |
| `BAZEL_MXC_DIR_GRANTS=1` | grant the parent directory of each read-only input file instead of the file (cheaper policy, exposes sibling files) |
| `BAZEL_MXC_NO_ENUM=1` | do not list the cwd and the grants' ancestors as enumerate-only |
| `BAZEL_MXC_NO_UI=1` | keep the Win32k lockdown (USER32 importers then fail) |
| `BAZEL_MXC_TIMING=<file>` | append per-action prep/spawn/wait milliseconds and grant counts |
| `BAZEL_MXC_DEBUG=1` | print the effective policy to stderr (`-D` does the same) |

## What the adapter does

For each action it builds a `ContainerRequest` with `Containment::ProcessContainer`
and calls `mxc_sdk::v1::spawn`, pumping the child's stdout/stderr to its own
(or to the `-l`/`-L` files):

- `-r` paths become `filesystem.readonlyPaths`, `-w` paths `readwritePaths`,
  `-b` paths `deniedPaths`. The execroot is a symlink forest and MXC evaluates
  policy on the resolved target, so every grant is also added for its
  `GetFinalPathNameByHandle` target.
- Declared outputs do not exist when the action starts, and the kernel policy
  cannot grant a non-existent file, so output grants are widened to the parent
  directory. (Per-file read-write grants on *existing* files work on .9550;
  they did not on .9457.)
- Bazel passes no `-W`; the adapter inherits its own cwd (the execroot) and
  lists it as enumerate-only when no grant covers it.
- Every ancestor of every grant and of the cwd, up to `C:\`, goes into
  `enumerate_paths` unless a grant already covers it (disable with
  `BAZEL_MXC_NO_ENUM`). MXC applies the *most restrictive* intent to a path
  listed twice, so enumerating a granted path would downgrade it. Enumeration
  grants listing only, no reads. Without this, `dir`, `realpath`, and launching
  an exe from a granted directory all fail with "Access is denied"
  (MXC issues 1109, 1162).
- The adapter's environment is passed verbatim (`inherit_default_environment
  = false`). MXC's "default environment" is the user's *profile* block, not
  the parent's, so with inheritance cl.exe lost `INCLUDE` and failed with
  C1083. MXC insists on `USERPROFILE` and `LOCALAPPDATA` being present, so
  those two are added when Bazel's scrubbed environment lacks them.
- Nested grants are pruned (a file under a granted directory is not listed
  again) and, with `BAZEL_MXC_DIR_GRANTS`, read-only file grants are replaced
  by their parent directory.
- UI: `ui.disable = false` and `ProcessContainerUiIsolation::Desktop` by
  default. Without that anything importing USER32 fails to initialise, as MXC
  documents (`BAZEL_MXC_NO_UI` restores the lockdown).
- Network: egress and ingress `deny`. Bazel has no flag for this on Windows
  yet; `--sandbox_default_allow_network` is not plumbed through.
- `-t` (kill delay) is accepted and ignored; `-T` becomes `timeout_ms`.

## Results

### Positive

`bazel build //...` of `example/`: genrule (`cmd_bat`), `cl.exe` compile and
`link.exe` link all run inside the container on the `base-container` tier.

### Enforcement

`example/neg/`, all tagged `manual`, built with `--keep_going`:

| action | `windows-sandbox` | `local` |
|---|---|---|
| read an undeclared source file | Access is denied | ok |
| write outside the declared outputs | Access is denied, no file created | ok (file appears) |
| launch an undeclared tool | Access is denied | ok |
| `curl https://api.github.com` | Could not resolve host | ok |

### Overhead

Standalone: `cmd /c exit 0` 27 ms bare vs 154 ms through `wxc-exec`;
`whoami` 51 vs 197 ms; `node -e 1` 102 vs 243 ms. Policy setup scales with the
number of granted paths at roughly 1 ms per path: 100 per-file grants 200 ms,
1 000 grants 950 ms, 10 000 grants 11.6 s per spawn. A single directory grant
costs the same as none.

Inside Bazel (8 vCPUs, warm server, after `bazel clean`):

| | `local` | `windows-sandbox` (MXC) |
|---|---|---|
| 40 trivial genrules, default jobs | 1.0 s | 3.0 s |
| 40 trivial genrules, `--jobs=1` | 2.5 s (62 ms/action) | 10.4 s (260 ms/action) |
| full `//...` of `example/` (43 sandboxed actions incl. cl/link) | | 5.1 s |

So about 200 ms fixed per action on top of Bazel's own ~60 ms Windows spawn
cost, plus ~1 ms per input. Parallelism hides most of the fixed cost; the
per-input cost will hurt actions with thousands of inputs (large C++ link
steps, JS bundles) unless inputs are granted by directory rather than by file.

## Building Bazel itself: Windows MXC sandbox vs. local vs. Linux sandbox

Workload: clean `bazel build //src:bazel-dev` of Bazel 9.3.0 from git (6 244
actions on Windows, 4 959 on Linux), `--jobs=16`, host Bazel = 9.3.0 built from
the same tree with the runner changes above (Windows) or the 9.3.0 release
(Linux), server shut down and `bazel clean` before every run, JSON trace
profile + compact execution log + memory profile + BEP written during the
profiled runs. Order: sandbox, sandbox, local, local, sandbox, local, then one
sandbox and one local run without profiling to check the profiler's own cost.
Bash-based mnemonics (`Genrule`, `ProtocAuthenticityCheck`) run locally in all
configurations. One machine per platform, nothing else running on it.

Hardware: Windows 11 Enterprise 25H2 26200.9550 on a 16-thread Intel Xeon D
class server, 64 GB; Linux (Talos, kernel 6.18) on a 16-thread Xeon D-1541
2.1 GHz, 128 GB, as a privileged pod on a drained Kubernetes node.

| configuration | wall time, s (runs in order) | mean | vs. local |
|---|---|---|---|
| Windows `--spawn_strategy=windows-sandbox` (MXC, per-file grants) | 3290, 3305, 3303 | 3299 | +59 % |
| Windows `--spawn_strategy=local` | 2103, 2074, 2034 | 2070 | |
| Linux `--spawn_strategy=linux-sandbox` | 1792, 1796, PENDING | | +1 % |
| Linux `--spawn_strategy=local` | 1773, 1765, PENDING | | |

Unprofiled check runs: PENDING.

Per action (box, mean over the run; profile "action processing" spans):

| mnemonic | count | Windows local | Windows MXC | Linux local | Linux sandbox |
|---|---|---|---|---|---|
| CppCompile | 1569 / 1582 | 7.6 s | 15.7 s | 7.5 s | 7.6 s |
| Javac | 1023 / 1024 | 17.5 s | 22.4 s | 14.5 s | 14.7 s |
| Turbine | 1010 | 1.0 s | 1.5 s | 0.5 s | 0.5 s |
| StampJarManifest | 100 | 1.2 s | 4.1 s | 0.8 s | 0.9 s |
| CppLink | 28 / 22 | 1.4 s | 3.5 s | 0.5 s | 0.5 s |

Where the Windows overhead goes (adapter's own timer, 3 686 timed actions per run,
three runs agree within 2 %):

| phase | median | mean | total per run |
|---|---|---|---|
| adapter: build policy | 29 ms | 0.1 s | 0.4 k s |
| MXC: create security environment + CreateProcess | 0.85 s | 2.6 s | 9.6 k s |
| the action itself inside the container | 2.7 s | 8.0 s | 29.6 k s |

The spawn cost is linear in the number of granted paths: a least-squares fit
over the 11 058 timed actions of the three runs gives 0.2 s + 6.5 ms per read
grant (5.5 ms per path when the enumerate-only ancestors are counted too),
with 16 actions in flight. Medians per bucket: 0.5 s under 500 grants, 4.5 s
at 500, 8.3 s at 1 000, 14.8 s at 2 000, 22 s above 2 500 (Javac actions have
up to 6 700 inputs; 55 % of all actions have fewer than 250). The
action itself also runs slower in the container: CppCompile about 2x, Javac
about 1.3x, which is file-access mediation cost, not the adapter.

Directory grants (`BAZEL_MXC_DIR_GRANTS=1`, measured on the 8-vCPU VM, same
protocol, one run each): local 2818 s, per-file grants 4455 s (+58 %),
directory grants 3853 s (+37 %). Spawn drops to a median of 0.26 s with
~20 grants per action; what remains is the in-container slowdown of the
actions themselves.

For reference, the default strategies (persistent Javac workers) built the
same tree in 1289 s on the VM against 2776 s with `--spawn_strategy=local`,
i.e. losing workers costs more than the sandbox does, and `windows-sandbox`
currently replaces the worker strategy for every mnemonic.

## Known limitations

- **Junction/symlink creation inside the container is denied.** This is by
  design: MXC issue 462 was a junction-based escape and the fix was to refuse
  junction creation outright. Bazel builds the execroot forest outside the
  sandbox so plain builds are fine, but actions that create symlinks (runfiles
  trees for tests, some rules_js actions) will fail.
- **git-bash / MSYS cannot run**: it starts, then dies accessing its shared
  `BaseNamedObjects` directory (MXC issue 1061). `genrule(cmd=...)`,
  `sh_binary`, `sh_test` and anything else going through `BAZEL_SH` will not
  work until that is fixed. `cmd_bat` genrules and native tools are fine.
- **`TEMP`/`TMP`/`LOCALAPPDATA` are rewritten inside the container** to a
  per-container `AppData\Local\Packages\sandbox.{guid}\AC\Temp`, whatever the
  adapter passes, so Bazel's `-w <TMP>` grant is not where tools actually
  write. Writing there works, but a directory the tool creates there with an
  owner-only DACL (Python's `tempfile.mkdtemp()` does that since the 2024
  hardening) is then inaccessible to the tool itself: the process-container
  token does not satisfy an owner-only ACL, while inside an explicitly granted
  path the policy makes it work. Consequence: zipped `py_binary` tools
  (`--build_python_zip`, the default on Windows) fail on extraction with
  `PermissionError`; `--nobuild_python_zip` avoids it and is what the
  measurements use for both configurations.
- **Interactive session required**, see above. CI agents running as a service
  will need a logged-on session (autologon + scheduled task with `/it`, or
  equivalent).
- **Toolchain roots are not declared inputs.** MSVC, the Windows Kits, node,
  Python, JDK etc. live outside the execroot and have to be granted via
  `BAZEL_MXC_EXTRA_RO`. A Bazel-side equivalent of
  `--sandbox_add_mount_pair`/`--sandbox_writable_path` for Windows would make
  this a proper flag instead of an `--action_env` hack.
- `--experimental_use_windows_sandbox` is still gated behind the (unrelated)
  `sandboxfs` wording in its help text, and the runner throws on unresolved
  symlinks in the execroot (`WindowsSandboxedSpawnRunner`).
- Tested only with Bazel 9.1.1/9.3.0 and a toy workspace. No Java, no Python,
  no tests (`bazel test`) yet.

## Bazel-side changes on this branch

Building Bazel itself (`//src:bazel-dev.exe`, ~6 200 actions) under
`--spawn_strategy=windows-sandbox` needed three changes to the runner, all in
`src/main/java/com/google/devtools/build/lib/sandbox/`:

- **Params file.** The runner passed every input as `-r <path>` on the command
  line; Javac actions with thousands of inputs exceed `CreateProcessW`'s 32 767
  character limit ("command is longer than CreateProcessW's limit"). The
  `-w/-r/-b` arguments are now written to `<tmpdir>/params` and passed as
  `@<file>` when the estimated command line exceeds 30 000 characters. The
  adapter expands `@file` (one argument per line).
- **Null inputs.** `SandboxInputs.getFiles()` maps empty virtual inputs to
  `null`; the runner dereferenced them and crashed the server (NPE) on a
  `rules_jvm_external` action. They are skipped now.
- **Temp directory cleanup.** `WindowsSandboxedSpawn.delete()` was empty, so the
  per-action `windows-sandbox.*` directories under the execroot were never
  removed. The spawn now deletes its directory.

The genrules of Bazel's own build use bash, which cannot run under MXC (issue
1061), so the measurements below use `--strategy=Genrule=local`.

## Possible Bazel-side follow-ups

Beyond the changes above, these would turn it into a supportable feature:

1. Pass the execroot explicitly (`-W`) and the toolchain roots (new flag) to
   the sandbox binary, instead of relying on the adapter's cwd and `--action_env`.
2. Plumb `--sandbox_default_allow_network` / `requires-network` through to
   the Windows runner.
3. Grant inputs by directory where possible (the per-path cost is linear).
4. Ship the adapter (a single static exe, nothing else to install) or let it
   be a Bazel module, so `--experimental_use_windows_sandbox=auto` can find it.

## `example/run.cmd` output (Bazel 9.3.0, 2026-10-11, abridged)

```
===== positive: genrule + cl.exe + link.exe, sandboxed
INFO: 48 processes: 5 internal, 43 windows-sandbox.
INFO: Build completed successfully, 48 total actions
hello from bazel
===== negative targets, sandboxed (expect 4 failures)
ERROR: .../neg/BUILD.bazel:6:8: Executing genrule //neg:undeclared_read failed: (Exit 1) ...
Access is denied.
ERROR: .../neg/BUILD.bazel:13:8: Executing genrule //neg:undeclared_write failed: (Exit 1) ...
Access is denied.
ERROR: .../neg/BUILD.bazel:28:8: Executing genrule //neg:undeclared_tool failed: (Exit 1) ...
Access is denied.
ERROR: .../neg/BUILD.bazel:20:8: Executing genrule //neg:network failed: (Exit 6) ...
curl: (6) Could not resolve host: api.github.com
ERROR: Build did NOT complete successfully
write was contained
===== negative targets, local (expect success)
INFO: 5 processes: 1 internal, 4 local.
INFO: Build completed successfully, 5 total actions
===== overhead: 40 trivial genrules, local vs sandboxed, --jobs=1
INFO: Elapsed time: 3.312s, Critical Path: 0.09s
INFO: Elapsed time: 9.492s, Critical Path: 0.25s
```
