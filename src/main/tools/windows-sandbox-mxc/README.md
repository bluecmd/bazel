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
build 26200.9550 (`example/run.cmd` output from the 9.3.0 run is at the end).

## Contents

| file | what |
|---|---|
| `BazelSandbox.c` | The adapter. Single C file, Win32 only. |
| `BUILD`, `build-adapter.cmd` | Build as `cc_binary` inside the Bazel tree, or standalone with MSVC. |
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
- MXC 1.0.0 (`wxc-exec.exe`, from the `@microsoft/mxc` npm package or the
  GitHub release). `wxc-exec.exe --probe` must report tier `base-container`
  and `baseContainerSupportsEnumeratePaths: true`.
- Bazel must run from an **interactive session** (console or RDP). From an
  SSH shell (session 0, network logon token, no interactive window station)
  every tool that imports `USER32.dll` (cl.exe, node, PowerShell, whoami, ...)
  dies inside the container with `STATUS_DLL_INIT_FAILED` (0xC0000142),
  whatever the UI policy says. This cost a day; it looks like an MXC bug and
  is not one.

## Usage

```
bazel build //... ^
  --experimental_use_windows_sandbox=yes ^
  --experimental_windows_sandbox_path=C:\path\to\BazelSandbox.exe ^
  --spawn_strategy=windows-sandbox ^
  --action_env=BAZEL_MXC_ENUM_CWD=1 ^
  --action_env=BAZEL_MXC_ENUM_ANCESTORS=1 ^
  --action_env=BAZEL_MXC_UI=1 ^
  "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits"
```

`wxc-exec.exe` is expected next to `BazelSandbox.exe` (or at `BAZEL_MXC_WXC`).
Bazel scrubs the action environment down to `PATH`/`TEMP`/`TMP`, so the adapter's
knobs have to come in through `--action_env`. `BAZEL_MXC_KEEP=1` keeps the
generated request JSON in `%TEMP%` for inspection.

## What the adapter does

For each action it writes a schema-1.0.0 request and runs `wxc-exec.exe` on it:

- `-r` paths become `filesystem.readonlyPaths`, `-w` paths `readwritePaths`,
  `-b` paths `deniedPaths`. The execroot is a symlink forest and MXC evaluates
  policy on the resolved target, so every grant is also added for its
  `GetFinalPathNameByHandle` target.
- Declared outputs do not exist when the action starts, and the kernel policy
  cannot grant a non-existent file, so output grants are widened to the parent
  directory. (Per-file read-write grants on *existing* files work on .9550;
  they did not on .9457.)
- Bazel passes no `-W`; the adapter inherits its own cwd (the execroot).
  `BAZEL_MXC_ENUM_CWD` lists it as enumerate-only when no grant covers it.
- `BAZEL_MXC_ENUM_ANCESTORS` lists every ancestor of every grant and of the
  cwd, up to `C:\`, in `processContainer.filesystem.enumeratePaths`, unless a
  grant already covers it. MXC applies the *most restrictive* intent to a path
  listed twice, so enumerating a granted path would downgrade it. Enumeration
  grants listing only, no reads. Without this, `dir`, `realpath`, and launching
  an exe from a granted directory all fail with "Access is denied"
  (MXC issues 1109, 1162).
- The adapter's environment is passed verbatim as `process.env`. MXC's
  "default environment" is the user's *profile* block, not the parent's, so
  with `inheritDefaultEnv` cl.exe lost `INCLUDE` and failed with C1083.
- `BAZEL_MXC_UI` emits `ui.disable=false` and
  `processContainer.ui.isolation="desktop"`. Without it anything importing
  USER32 fails to initialise, as MXC documents.
- Network: egress and ingress `deny`. Bazel has no flag for this on Windows
  yet; `--sandbox_default_allow_network` is not plumbed through.
- `-t` (kill delay) is accepted and ignored; `-T` becomes `process.timeout`.

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

## Possible Bazel-side follow-ups

None of these were needed for the experiment, but they would turn it into a
supportable feature:

1. Pass the execroot explicitly (`-W`) and the toolchain roots (new flag) to
   the sandbox binary, instead of relying on the adapter's cwd and `--action_env`.
2. Plumb `--sandbox_default_allow_network` / `requires-network` through to
   the Windows runner.
3. Grant inputs by directory where possible (the per-path cost is linear).
4. Ship or fetch `wxc-exec.exe` + the adapter, or let the adapter be a Bazel
   module, so `--experimental_use_windows_sandbox=auto` can find it.

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
