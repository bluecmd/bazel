# What is missing to build Bazel with every action sandboxed through `BazelSandbox.exe` on PSEC

Branch `windows-sandbox-psec-exe`. The question: a clean build of Bazel 9.3.0
on Windows runs sandboxed today except for the bash-launched mnemonics
(`Genrule`, `ProtocAuthenticityCheck`), which are forced local. What is
missing, feature by feature, to run **every** action of Bazel's own build
through the classic `--experimental_use_windows_sandbox` path with a
`BazelSandbox.exe` that calls the OS primitive directly
(`CreateProcessSecurityEnvironment` in `processmodel.dll`, "PSEC", no MXC
SDK)?

Everything below was measured on Windows 11 25H2 26200.9550
(`processmodel.dll` 10.0.26100.9549, PSEC contract 1.1, support flags `0xF`),
with Bazel 9.3.0 plus the four `windows-sandbox` runner fixes of this branch
as the host, building the 9.3.0 tree (`//src:bazel-dev.exe`, 6 244 actions).
Two machines: the 8-vCPU VM (`bazel-mxc`, user `mxc`) for the experiments and
the all-sandboxed builds, the 16-thread box (`shibsrv`) for the reference
build with today's exclusions. Section 7 lists every experiment with the
command that reproduces it.

## 0. Summary

| configuration | result |
|---|---|
| today: `windows-sandbox` + native exe, `Genrule` and `ProtocAuthenticityCheck` local (box, `--jobs=16`, directory grants) | **builds**: 6 244 processes = 1 384 internal, 138 local, 4 768 `windows-sandbox`; 2 825 s wall (the Rust MXC adapter with directory grants took 2 866 s on the same box, `local` 2 022-2 070 s) |
| every action through `windows-sandbox`, git-bash as the shell (VM) | 1 536 actions sandboxed, then 117 `Genrule`/`ProtocAuthenticityCheck` actions fail (git-bash dies at start), 1 `local = 1` genrule refused, 1 `cmd_bat` genrule failed (adapter bug, fixed); everything downstream of the bash genrules (~3 000 actions, all of the Java tree) never runs |
| every action through `windows-sandbox`, busybox-w32 as the genrule shell (box, `--jobs=16`, long-path exe) | 3 623 processes (2 253 sandboxed) in 955 s, then stops at 6 229 of 6 244 with 8 failing actions: 2 `sh_binary` tools whose launcher runs git-bash (`minimize_jdk`, `zip_builtins`), 5 genrules whose last command is killed because busybox does not wait for it (4.7), the `local = 1` genrule |
| **… plus the knobs through `--host_action_env` too (box, `--jobs=16`): the final state** | **6 238 of 6 244 actions done, 4 897 `windows-sandbox` + 1 387 internal, 0 local, 2 944 s** (vs 2 825 s with 138 local bash actions). 3 actions remain: `//tools/osx:xcode-locator-genrule` (`local = 1`), `//src:embedded_jdk_allmodules` (`minimize_jdk.sh` needs bash proper, 4.8), protobuf's `ProtocAuthenticityCheck` (a `run_shell` action without `use_default_shell_env`, so it gets no `--action_env` at all and the shell directory is not granted, gap 20) |
| … plus busybox as the sh toolchain (`--repo_env=BAZEL_SH`) and the confined trampoline (box) | 3 624 processes (2 253 sandboxed) in 1 020 s, stops at 6 229: `zip_builtins` now passes; `minimize_jdk.sh` fails under busybox's ash (the bash runfiles bootstrap `source "${RUNFILES_DIR:-/dev/null}/$f" \|\| …` makes a POSIX shell exit, 4.8); fastutil + 4 upb genrules still fail at `$(…)` ("unable to spawn shell", 4.7); the `local = 1` genrule |
| `bazel test` of a cc/java/py/sh test each, sandboxed | cc, java, py **pass** (runfiles manifest, `TEST_TMPDIR`, undeclared outputs, zipped `py_test`); `sh_test` fails with git-bash as the sh toolchain (gap 18) and **passes** with busybox as the sh toolchain plus the trampoline (`tests2.cmd`: 4 of 4) |

The one blocker that matters is **the MSYS runtime (git-bash) cannot start
inside a process security environment**, and the reason is now exact: the
environment runs the action as an **AppContainer** (lowbox) token, and the
MSYS runtime (3.6.10 in Git for Windows 2.56) creates its shared objects in
places and with DACLs that an AppContainer cannot use. Both failure points are
in `msys-2.0.dll`, fixable there (toolchain), or avoidable by Microsoft adding
a non-AppContainer identity to PSEC. Everything else found is either already
fixed in the exe (adapter), a Bazel flag or rule tweak (Bazel side), or a
small OS behaviour with a documented workaround.

## 1. The exe (`psec/BazelSandbox.cpp`)

`psec/BazelSandbox.cpp` + `psec/build.cmd` (VS 2022 Build Tools, one `cl`
line, no dependencies) implement the `WindowsSandboxedSpawnRunner` contract
(`-W -T -t -l -L -w -r -b -D @params -- cmd`) on PSEC directly: the policy
rules of the Rust MXC adapter (`src/main.rs`, README), the FlatBuffer encoder
and API declarations of `src/main/native/windows/psec.cc` on branch
`windows-sandbox-psec-jni`, inherited stdio, a kill-on-close job, timeout =
terminate the job. It passed the example workspace (`example/run.cmd`:
positive build sandboxed, the four negative targets denied, write contained)
on the first run.

Two adapter-side bugs surfaced in Bazel's tree and are fixed on this branch
(class **c**):

* **cmd.exe arguments must be passed verbatim.** Bazel's
  `WindowsSubprocessFactory.escapeArgvRest` appends the arguments of `cmd.exe`
  unescaped; a `cmd_bat` genrule hands its whole command, embedded quotes
  included, as one argument. Quoting it the CRT way (`\"`) made
  `@zlib//:copy_public_headers` fail with "The system cannot find the path
  specified". The exe now special-cases `cmd.exe` like Bazel does.
* **Runfiles directories must be read-write** (see gap 5): `tw.exe`'s
  `SetCurrentDirectory` into the read-only-granted `<test>.exe.runfiles`
  directory is denied, so every test failed.

Experiment knobs added for this document: `BAZEL_PSEC_NET=1` (egress allow +
`internetClient`), `BAZEL_PSEC_CAPS`, `BAZEL_PSEC_UI_MASK`,
`BAZEL_PSEC_SHORT_TMP`, `BAZEL_PSEC_NO_SANDBOX=1` (A/B), `BAZEL_PSEC_LOG`
(policy of every failed action), `BAZEL_PSEC_EXTRA_RW`,
`BAZEL_PSEC_RUNFILES_RO`, `BAZEL_PSEC_NO_WIDEN`, `BAZEL_PSEC_NO_TMPDIR`.

## 2. What the contained process is

Measured from inside an environment with the probe `nttest.exe` (section 7):

* `TokenIsAppContainer = 1`, package SID `S-1-15-2-916310712-…`, one
  capability SID, integrity level **Low** (`S-1-16-4096`), privileges
  reduced to `SeChangeNotifyPrivilege` and `SeIncreaseWorkingSetPrivilege`
  (an administrator's token loses `SeCreateSymbolicLinkPrivilege` etc.),
  session of the parent (0 under ssh, 1 interactively).
* Process mitigations forced on: `ASLR.EnableForceRelocateImages = 1`,
  `ASLR.DisallowStrippedImages = 1`, `StrictHandleCheck = 1` (outside: 0, 0,
  0). Win32k lockdown off (the spec's `disallow_win32k_system_calls = false`).
* `TEMP`/`TMP` rewritten to `…\AppData\Local\Packages\sandbox.{guid}\AC\Temp`,
  `LOCALAPPDATA` to `…\sandbox.{guid}\AC`; `TMPDIR` passes through.
* Named pipes (`\\.\pipe\x`, `\\.\pipe\LOCAL\x`), events and sections
  (plain and `Global\`) can be **created** from inside. 32-bit (WoW64)
  processes run. Network: `curl` fails with "Could not resolve host" under
  the default policy and gets HTTP 200 with egress allow.

## 3. Gap table

Classes: **a** Windows/PSEC limitation, **b** Bazel side (runner, rules,
flags, Bazel's own BUILD files), **c** adapter (`BazelSandbox.exe`), **d**
toolchain (MSYS, busybox, rules_*, binaries). "Today" is `--spawn_strategy=windows-sandbox`
with no exclusions. Counts are from the 9.3.0 tree on Windows (`aquery`).

| # | action type / mechanism | actions | today | root cause (section 4) | class | proposed fix | cost |
|---|---|---|---|---|---|---|---|
| 1 | `Genrule` with `cmd` (bash), `ProtocAuthenticityCheck`, `sh_binary` tools run by genrules (`minimize_jdk`, `generate_jvm_module_options.sh`), `sh_test` | 117 genrule/protoc actions in the build; ~3 000 downstream actions blocked | fail: `bash.exe` exits 0xC0000142 at start | MSYS runtime: (1) `NtCreateDirectoryObject(\BaseNamedObjects\msys-2.0S5-<key>)` → `STATUS_ACCESS_DENIED`, the directory's DACL has no AppContainer ACE; (2) with the directories pre-created, the signal pipe's write end cannot be reopened: `NtOpenFile(\Device\NamedPipe\LOCAL\msys-<key>-<pid>-sigwait, GENERIC_WRITE)` → `ACCESS DENIED`, the pipe's DACL (`sec_user_nih`: user + SYSTEM) fails the AppContainer package check | **d** (MSYS), or **a** | patch `msys2-runtime` (`winsup/cygwin/mm/shared.cc`, `sec_helper.cc`): when `TokenIsAppContainer`, use `\Sessions\<n>\AppContainerNamedObjects\<package SID>` as the shared parent directory and add an ACE for the package SID (or `S-1-15-2-1`) to the descriptors MSYS puts on its pipes, sections and symlinks; ship in Git for Windows / MSYS2. Alternative: Microsoft adds a non-AppContainer identity (restricted token + job + BFS, no lowbox) to the PSEC spec | ~150 lines in the runtime + a rebuild of `msys-2.0.dll`; 1-2 days, then upstream lead time. Workaround now: busybox-w32 as `--shell_executable` (gap 13) |
| 2 | `genrule(local = 1)`: `//tools/osx:xcode-locator-genrule` (`cp $< $@` on Windows) | 1 | refused: "cannot be executed with any of the available strategies: [windows-sandbox]" | the rule asks for `local`; `--spawn_strategy=windows-sandbox` has no fallback | **b** (tree) | drop `local = 1` (only needed for the macOS `xcrun` branch), or `select` it; otherwise `--spawn_strategy=windows-sandbox,local` keeps exactly this action local | minutes |
| 3 | `Genrule` with `cmd_bat` (`@zlib//:copy_public_headers`), `CopyFile` (`cmd.exe /C x.bat`) | 1 + 2 | failed before the fix, pass now | adapter quoted `cmd.exe` arguments the CRT way | **c** fixed | — | done |
| 4 | `Genrule` with `cmd_ps` (`@zstd-jni//:version-java`) | 2 | pass, with a printed error | Bazel's `cmd_ps` prologue runs `Set-ExecutionPolicy -Scope CurrentUser`, an HKCU write an AppContainer cannot do (`UnauthorizedAccessException`); the action still exits 0 | **b** | `WindowsPowershellCommandConstructor`: `-ExecutionPolicy Bypass` on the command line instead of the registry write | minutes |
| 5 | anything that changes directory into a read-only or enumerate-only grant: the test wrapper `tw.exe` (`chdir` to `<test>.exe.runfiles\_main`), genrule `cd` into a source directory, PowerShell's current-location open, busybox `cd` | all tests (4/4 failed), rare in build actions | tests fail with "Could not chdir … value: 5" | `bfs.sys` denies `FILE_TRAVERSE` opens under read-only and enumerate-only grants: `NtOpenFile(dir, FILE_TRAVERSE\|SYNCHRONIZE, FILE_DIRECTORY_FILE\|FILE_SYNCHRONOUS_IO_NONALERT\|FILE_OPEN_FOR_BACKUP_INTENT)` → `0xC0000022` (what `SetCurrentDirectoryW` does); `FILE_LIST_DIRECTORY` and `FILE_READ_ATTRIBUTES` opens of the same directory succeed; under a read-write grant all succeed | **a**, with **c**/**b** workarounds | exe: grant `*.runfiles` directories read-write (done); runner: pass the runfiles directory as writable; Microsoft: allow `FILE_TRAVERSE` on read-only grants (it grants nothing a read grant does not) | done / minutes / Microsoft |
| 6 | junction creation inside the environment (`mklink /J`, rules that build their own trees) | 0 in Bazel's build (Bazel creates the execroot forest and runfiles manifests outside) | denied | `FSCTL_SET_REPARSE_POINT` → `ERROR_ACCESS_DENIED` even in a read-write grant (by design since MXC #462); `CreateHardLinkW` → `ERROR_ACCESS_DENIED` too | **a** | none needed for Bazel's build; actions that need junctions stay local | — |
| 7 | symlink creation inside the environment (`--enable_runfiles`-style trees built by an action, `ctx.actions.symlink` is server-side) | 0 | denied unless Developer Mode | `CreateSymbolicLinkW` → `ERROR_PRIVILEGE_NOT_HELD` (1314): the lowbox token has no `SeCreateSymbolicLinkPrivilege`; with Developer Mode (`AllowDevelopmentWithoutDevLicense=1`) and `SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE` file and directory symlinks are created inside a read-write grant | **d** (machine setup) | enable Developer Mode, which Bazel on Windows recommends anyway | minutes |
| 8 | relocation-stripped binaries (old 32-bit tools, e.g. Info-ZIP 3.0 `zip.exe` from GOW) | 0 in the tree's declared tools | `CreateProcessW` fails with 623 `ERROR_ILLEGAL_DLL_RELOCATION` | PSEC forces `ForceRelocateImages` + `DisallowStrippedImages` (mandatory ASLR) | **a** | use relocatable builds (the native Info-ZIP built with MSVC in section 7 runs) | — |
| 9 | zipped `py_binary` tools (`--build_python_zip`, default on Windows): rules_pkg `build_tar`, `proguard_allowlister` | 3 | pass | `TEMP` is redirected to the container's `AC\Temp`, where Python's owner-only `mkdtemp` directory is unusable by the token; the exe sets `TMPDIR` to the action's granted temp dir and Python prefers it | **a** with **c** workaround in place | keep `TMPDIR`; a Bazel-side `--sandbox_tmpfs`-like short temp root would avoid `MAX_PATH` on deep execroots (not hit here) | done |
| 10 | network-requiring actions (`requires-network` tag) | 0 | always denied | the Windows runner never passes a network intent; the exe can allow egress per action (`BAZEL_PSEC_NET`) | **b** | plumb `requires-network` / `--sandbox_default_allow_network` into `WindowsSandboxUtil` (new `-N` flag) | hours |
| 11 | toolchain roots outside the execroot (MSVC, Windows Kits; a local JDK/Python/node) | every C++ action | work via `--action_env=BAZEL_MXC_EXTRA_RO` | not declared inputs | **b** | a repeatable `--experimental_windows_sandbox_readonly_root` (exists on the JNI branch) emitted as `-r` | hours |
| 12 | the shell executable and its directory (`--shell_executable`, `BAZEL_SH`): MSYS forks by re-executing `bash.exe`, busybox spawns itself for `$(…)`/pipes, PATH tools live next to it | every bash genrule | busybox: "unable to spawn shell" for `$(dirname …)` | the shell is argv[0], not an input; only the first process is created by the unconfined exe | **b** | grant the shell's directory (and the `usr\bin`/`bin` directories Bazel puts on PATH) read-only; today: add them to `BAZEL_MXC_EXTRA_RO` | hours |
| 13 | busybox-w32 as the shell (`--shell_executable`) | 117 | works for 136 of the 138 bash actions once the items in this row, the trampoline (4.7) and gap 20 are in place; `minimize_jdk.sh` (4.8) and `ProtocAuthenticityCheck` (gap 20) remain | busybox is a plain Win32 program and starts fine in the environment; its own gaps: `MAX_PATH` (needs `LongPathsEnabled=1` **and** a `longPathAware` manifest, which the stock exe lacks: `cp` of the long maven paths fails with "can't stat"), no `zip` applet (`zip -qd` in `//third_party:filter_netty_dynamic_libs` and `fastutil_stripped_jar`: a native Info-ZIP is needed on PATH), no `locale` (`minimize_jdk.sh`), the bash runfiles library (`runfiles.bash`) is not ash-compatible | **d** | ship a long-path-aware busybox + native zip next to it; fix the two scripts, or keep `sh_binary` tools on git-bash until gap 1 is closed | hours |
| 14 | persistent workers (`Javac`, `Turbine`, …) | 2 028 | run **unsandboxed** under the default strategy; `--spawn_strategy=windows-sandbox` disables them (and doubles build time) | no sandboxed-worker support on Windows (`SandboxedWorker` only knows the Linux/Darwin sandboxes) | **b** | start worker processes through the same attach path with a fixed per-worker policy (worker execroot read-write, toolchain roots read-only); the handle can be attached to a long-lived process, environments are reusable (JNI branch) | days |
| 15 | USER32 importers from session 0 (ssh, services) | every `cl.exe`, `java.exe`, … | die with `STATUS_DLL_INIT_FAILED` | interactive window station required (MXC #1465) | **a** | run Bazel from an interactive session (autologon + scheduled task with `/it`) | — |
| 16 | internal actions (`Symlink`, `SymlinkTree`, `RunfilesTree`, `FileWrite`, `TemplateExpand`, `SourceSymlinkManifest`, `RepoMappingManifest`) | 2 893 | run in the server, nothing to sandbox | — | — | — | — |
| 17 | `cc_test`, `java_test`, `py_test` under `bazel test` (runfiles manifest, `TEST_TMPDIR`, undeclared outputs, zipped `py_test`) | — | pass with the runfiles-rw exe (failed before, gap 5) | — | **c** fixed | — | done |
| 18 | `sh_test` / `sh_binary` launchers | — | fail: the launcher runs the sh toolchain's bash (`BAZEL_SH` at repository-fetch time, Git's MSYS bash), whatever `--shell_executable` says | gap 1 again; `--shell_executable` does not reach `local_config_sh` | **b**/**d** | `--repo_env=BAZEL_SH=<busybox>` for the toolchain, or the MSYS fix | minutes / gap 1 |
| 20 | the adapter's knobs travel as environment variables (`--action_env=BAZEL_MXC_EXTRA_RO=…` etc.) | every exec-configuration (`[for tool]`) action | the toolchain roots, directory grants and trampoline silently do not apply to `[for tool]` actions: `--action_env` is target-configuration only, exec-configuration actions take `--host_action_env` (`CoreOptions`); this is what made the four upb bootstrap genrules and `fastutil_stripped_jar [for tool]` fail ("unable to spawn shell": busybox cannot stat its own image, `CreateFile C:\mxc\psecexe\tools\bash.exe` → `ACCESS DENIED` in the trace) while identical target-configuration genrules passed | `--action_env` semantics | **b** | the runner gets proper flags (gap 11, 12) instead of `--action_env`; until then pass every knob through both `--action_env` and `--host_action_env` | minutes |
| 19 | the action's temp directory | every action | the user's shared `%TEMP%` is granted read-write to every action | `WindowsLocalEnvProvider` keeps the client's `TMP`/`TEMP` and `getWritableDirs` grants it; the per-action `windows-sandbox.<n>\work` directory is only used when the client has no `TMP` | **b** | set `TMP`/`TEMP`/`TMPDIR` to the per-action directory, as the JNI branch does (`<output_base>\psec\<n>`, short on purpose) | hours |

Notes on the counts: 6 244 actions in the build; 2 893 are internal
(gap 16), 1 536 + 1 496 internal ran in the all-sandboxed git-bash run
before the bash failures stopped the Java tree. The `Genrule` count of 137
includes 2 `cmd_bat`/`cmd_ps` genrules that do not use bash; the 117 that
failed are the `cmd` genrules reached before the build stopped (`cp`
genrules of `rules_jvm_external` and `rules_java`, `//src:embedded_jdk_*`,
`//src/main/starlark/builtins_bzl:builtins_bzl_zip`, `//third_party:*`,
protobuf's upb bootstrap) plus `ProtocAuthenticityCheck`.

## 4. Root causes at the OS boundary

### 4.1 git-bash: two AppContainer access checks (gap 1)

`bash.exe -c "echo hi"` inside an environment that grants `C:\Program Files\Git`
read-only:

```
bash (4960) C:\Program Files\Git\usr\bin\bash.exe: *** fatal error -
  NtCreateDirectoryObject(\BaseNamedObjects\msys-2.0S5-1888ae32e00d56aa): 0xC0000022
```

`get_shared_parent_dir()` in `winsup/cygwin/mm/shared.cc` creates
`\BaseNamedObjects\<shared_id>-<installation key>` with `OBJ_OPENIF` and an
"everyone" security descriptor, and `api_fatal`s on failure. The DACLs of the
object directories, read with `bnodir.exe acl` (SDDL):

| directory | DACL |
|---|---|
| `\BaseNamedObjects` | `(A;;CCDCLCSWRC;;;WD)(A;;DC;;;RC)(A;;…;;;S-1-5-90-0-0)(A;;…;;;SY)` |
| `\Sessions\1\BaseNamedObjects` | `…(A;CI;CCDC;;;WD)(A;;DC;;;RC)` and the user's SID |
| `\Sessions\1\AppContainerNamedObjects` | the same plus `(A;;CCDC;;;S-1-15-2-2)(A;;CCDC;;;AC)` |

Only the AppContainer directory carries an ACE for `ALL APPLICATION PACKAGES`
(`AC`) and `ALL RESTRICTED APPLICATION PACKAGES` (`S-1-15-2-2`). An
AppContainer access check needs both the user part and the package part of
the DACL to grant; "Everyone" does not satisfy the package part, so the
creation in `\BaseNamedObjects` (and the second choice,
`\Sessions\BNOLINKS\<n>\…` = `\Sessions\<n>\BaseNamedObjects`) is denied.

To see what comes next, `bnodir.exe hold` created both directories from
outside with `(A;;GA;;;WD)(A;;GA;;;AC)(A;;GA;;;S-1-15-2-2)`. bash then gets
further and dies in `sigproc_init`:

```
bash (8156): *** fatal error - couldn't create signal pipe, Win32 error 5
```

Process Monitor shows the call: the pipe is created
(`NtCreateNamedPipeFile` succeeds), then

```
bash.exe 8156 CreateFile \Device\NamedPipe\LOCAL\msys-1888ae32e00d56aa-8156-sigwait
  ACCESS DENIED  Desired Access: Generic Write, Read Attributes, Options: Synchronous IO Non-Alert
```

This is `fhandler_pipe::nt_create`'s `NtOpenFile` of the write end. The pipe
was created with `sec_user_nih(cygheap->user.sid())`, a DACL naming only the
user and SYSTEM. The AppContainer process that created it cannot reopen it:
the package part of the check has no ACE to match. The same pattern applies
to every MSYS object that carries an explicit descriptor (`cygpid.<n>`
sections, `winpid.<n>` symbolic links, the `sig_send` mutexes), so this is not
one call to patch but one helper: when the token is an AppContainer
(`GetTokenInformation(TokenIsAppContainer)`), MSYS must (1) put its shared
directory under `\Sessions\<n>\AppContainerNamedObjects\<package SID>` (the
per-package directory the kernel already provides) and (2) include the
package SID, or `S-1-15-2-1`, in `everyone_sd()` / `sec_user*()`. Both are in
`winsup/cygwin` (`mm/shared.cc`, `sec_helper.cc`); nothing in bash or
coreutils changes. Microsoft's alternative is a PSEC identity that is not an
AppContainer (the BFS path policy and the job do not depend on it), which
would also lift gaps 7 (privilege) and the `TEMP` rewrite (gap 9).

What was ruled out: named pipes, events and sections themselves are allowed
(`nttest.exe pipe/event/section` all succeed, including
`\\.\pipe\msys-<key>-…`); the `BAZEL_PSEC_CAPS` capabilities string changes
nothing because no capability maps to the global object namespace; WSL is not
installed and would not be contained anyway; MSYS2's own bash is the same
3.6.x runtime; Cygwin proper has the same `shared.cc`.

### 4.2 `FILE_TRAVERSE` under read-only grants (gap 5)

`nttest.exe ntopen` matrix, `in` = read-only grant, `t` = enumerate-only
ancestor, `out` = read-write grant (status codes; `C000000D` =
`STATUS_INVALID_PARAMETER` for option combinations Windows itself rejects):

| access \ options | `0` | `DIRECTORY_FILE` | `DIRECTORY_FILE+SYNC_IO` | `+BACKUP_INTENT` |
|---|---|---|---|---|
| `FILE_TRAVERSE` on `in` | OK | **C0000022** | C000000D | C000000D |
| `FILE_TRAVERSE\|SYNCHRONIZE` on `in` | OK | **C0000022** | **C0000022** | **C0000022** |
| `FILE_LIST_DIRECTORY[\|SYNCHRONIZE]` on `in` | OK | OK | OK | OK |
| `FILE_READ_ATTRIBUTES[\|SYNCHRONIZE]` on `in` | OK | OK | OK | OK |
| `FILE_TRAVERSE[\|SYNCHRONIZE]` on `t` (enumerate-only) | **C0000022** | **C0000022** | **C0000022** | **C0000022** |
| `FILE_LIST_DIRECTORY` on `t` | OK | OK | OK | OK |
| `FILE_TRAVERSE\|SYNCHRONIZE` on `out` | OK | OK | OK | OK |

`SetCurrentDirectoryW` is exactly the denied row (`RtlSetCurrentDirectory_U`
opens with `FILE_TRAVERSE|SYNCHRONIZE`, `FILE_DIRECTORY_FILE |
FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT`). The initial
working directory of the action is fine because `CreateProcessW` is called by
the unconfined exe. Consequences seen: `cmd /c cd /d <ro dir>` → "Access is
denied"; busybox `cd in` → "Permission denied"; PowerShell's open of its
start directory → `ACCESS DENIED Execute/Traverse, Synchronize, Options:
Directory`; `tw.exe` → `Could not chdir … value: 5` for every test, since
`<test>.exe.runfiles` is granted read-only by the runner.

### 4.3 Links (gaps 6, 7)

Inside a read-write grant, with Developer Mode off:
`CreateSymbolicLinkW(…, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)` →
1314; `CreateDirectoryW` + `FSCTL_SET_REPARSE_POINT(IO_REPARSE_TAG_MOUNT_POINT)`
→ 5 (the directory is created, the reparse point is refused);
`CreateHardLinkW` to a read-only or read-write file → 5. The same calls
outside the environment succeed. With
`HKLM\…\AppModelUnlock\AllowDevelopmentWithoutDevLicense = 1` the two symlink
calls succeed inside the environment (file and directory symlink both
created); junctions and hard links stay denied.

### 4.4 Mandatory ASLR (gap 8)

`GetProcessMitigationPolicy` inside vs outside: `EnableForceRelocateImages`
1 vs 0, `DisallowStrippedImages` 1 vs 0, `RaiseExceptionOnInvalidHandleReference`
1 vs 0; DEP, CFG, dynamic code, signature, image-load, child-process and
extension-point policies unchanged. The GOW `zip.exe` (x86, "Relocations
stripped", image base 0x400000) therefore fails at `CreateProcessW` with 623
`ERROR_ILLEGAL_DLL_RELOCATION`; a 32-bit `cmd.exe` (relocatable) runs.

### 4.5 PowerShell (gap 4)

`powershell -NoProfile -Command` with the exact `cmd_ps` prologue Bazel
generates (`WindowsPowershellCommandConstructor`):
`Set-ExecutionPolicy : Access to the registry key
'HKEY_CURRENT_USER\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'
is denied`, then the script runs (`Get-Content` of a granted input,
`Set-Content` of an output) and the process exits 0. Process Monitor also
shows PowerShell's startup trying `RegCreateKey HKLM\…\SystemCertificates\*`
(denied, harmless). Without the prologue there is no error at all.

### 4.6 Temp (gap 9)

Inside the environment `TMP`/`TEMP` =
`C:\Users\mxc\AppData\Local\Packages\sandbox.{guid}\AC\Temp` whatever the
exe passes, `LOCALAPPDATA` = `…\sandbox.{guid}\AC`, `TMPDIR` untouched. The
all-sandboxed build ran rules_pkg's zipped `build_tar` (`PackageTar`) with
`TMPDIR` = Bazel's `<execroot>\windows-sandbox.<n>\work`; it extracted and
ran.

### 4.7 busybox does not wait for its last command inside the environment (gap 13)

With busybox as the shell, five genrules of the all-sandboxed build failed
although every one of them passes when its exact grants and command are
replayed by hand (`upb1.cmd`, `spawn*.cmd`, 160 concurrent replays in
`stress1.cmd`, 0 failures). A Process Monitor trace of the real action
(`pmgen2.cmd`, box) shows the sequence: `bash.exe` starts, spawns its
`sh --fs` helper for `$(dirname …)` (exit 0), spawns `protoc_minimal.exe`,
and **exits with status 0 five milliseconds later**; `BazelSandbox.exe`
then closes its kill-on-close job and protoc dies after resolving its DLLs,
having written nothing ("declared output … was not created"). The timing
probe confirms it (`wait2.cmd`): `bash -c "nttest sleep 3000"` returns after
0.2 s inside an environment and after 3 s outside; `bash -c "nttest sleep
3000; echo after"` (not the last command) waits in both.

The cause is in busybox-w32's `exec` path: `wait_for_child()` in
`win32/process.c` begins with `if (getppid() == 1) exit(0);`, and
`getppid()` walks a Toolhelp process snapshot. Inside the AppContainer the
snapshot shows only the container's own processes (`busybox ps`: the shell,
its `conhost.exe`, the applet; PPID 1), the unconfined parent
`BazelSandbox.exe` is invisible, so busybox believes it is orphaned and
exits without waiting. The "unable to spawn shell" failures of the same
genrules are the same mechanism one step earlier. Two fixes:

* **exe (c, done):** `BAZEL_PSEC_TRAMPOLINE=1` runs the action as
  `BazelSandbox.exe --run -- <cmd>` inside the environment, so the shell's
  parent is a confined process it can see; `bash -c "nttest sleep 3000"`
  then takes 3 s and prints its output, and `ps` shows the parent. Cost: one
  extra process per action (~10 ms).
* **busybox (d):** `getppid()` from
  `NtQueryInformationProcess(ProcessBasicInformation).InheritedFromUniqueProcessId`
  instead of a snapshot walk; a few lines.

### 4.8 Bazel's bash runfiles bootstrap under busybox's ash (gap 13)

`minimize_jdk.sh` (and every script that pastes Bazel's runfiles
boilerplate) begins with

```
source "${RUNFILES_DIR:-/dev/null}/$f" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "${RUNFILES_MANIFEST_FILE:-/dev/null}" | cut -f2- -d' ')" 2>/dev/null || …
```

In bash a failing `source` inside a `||` list continues to the next
alternative. In a POSIX shell `.` is a special builtin and a failing one
terminates a non-interactive shell; busybox's ash does exactly that
(`bash -x`: `+ source /dev/null/bazel_tools/tools/bash/runfiles/runfiles.bash`,
then exit 0, no message, outside the sandbox too). So any `sh_binary` that
uses the runfiles library needs bash proper, i.e. the MSYS fix (gap 1), or
a rewrite of its bootstrap. `zip_builtins.sh` (no runfiles library) runs
fine under busybox once the sh toolchain points at it.

## 4.9 In the kernel: `bfs.sys` on a KDNET target

The two OS behaviours that matter most, the `FILE_TRAVERSE` denial (4.2) and
the per-file cost (section 0), were taken down to the filter driver on a
kernel-debugged VM (`kdt` target `psec2`, golden image `vdi/win11-golden-9550`
= the pipeline's `win11-patched:26H2-26300.9550`, kernel 10.0.26100.9549,
`bfs.sys` byte-identical to the experiment VM's, SHA-256 `5f86642c…`). The
driver has no public symbols on Microsoft's server (404 for its PDB GUID),
but the binary's functions are fully named (IDA, `psec/experiments/bfs-funcs.txt`),
and ntoseye resolves the same names, so breakpoints by name work.

### 4.9.1 `FILE_TRAVERSE` is denied by one access-mask constant

`bfs!BfsQueryAccessOnly(int kind, PFLT_CALLBACK_DATA data)` decides whether an
open under a **read-only** grant (policy value 2) is "query-only" and may
proceed. `kind` is 2 when `Create.Options` has `FILE_DIRECTORY_FILE`, else 1.
The function reads `OriginalDesiredAccess` from the create's access state and
tests it against one of three constants:

```
cmp   esi, 2                      ; directory open?
jnz   file
test  ebx, 0FFE1FF7Eh             ; directory: allowed = 0x001E0081
jmp   done                        ;   FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
file:
call  Feature_BfsQueryOnlyAllowExecute…   ; (on in this build)
test  ebx, 0FFE1FF56h             ; file: allowed = 0x001E00A9 = … | FILE_READ_DATA | FILE_READ_EA | FILE_EXECUTE
test  ebx, 0FFE1FF76h             ; file, feature off
setz  al
```

`FILE_EXECUTE` and `FILE_TRAVERSE` are the same bit (0x20). The
`BfsQueryOnlyAllowExecute` feature added it to the **file** mask only; the
**directory** mask never got it. Live, with a breakpoint on the function and
`nttest ntopen` inside an environment that grants `C:\kd\files` read-only:

| open | `kind` (rcx) | `OriginalDesiredAccess` | `Create.Options` | calls | result |
|---|---|---|---|---|---|
| `FILE_TRAVERSE`, `FILE_DIRECTORY_FILE` | 2 | 0x20 | 0x01000001 | 2 (the read-only path calls it again when it returns false) | `STATUS_ACCESS_DENIED` |
| `FILE_TRAVERSE`, no options | 1 | 0x20 | 0x01000000 | 1 | success |
| `FILE_LIST_DIRECTORY`, `FILE_DIRECTORY_FILE` | 2 | 0x01 | 0x01000001 | 1 | success |

Stack at the breakpoint: `bfs!BfsQueryAccessOnly` ← `bfs!BfsCheckAndApplyPolicy+0xa0d`
← `bfs!BfsPreCreateOperation+0x76b` ← `fltmgr!FltpPerformPreCallbacksWorker`
← `fltmgr!FltpCreate`. `SetCurrentDirectory` always opens with
`FILE_TRAVERSE | SYNCHRONIZE` and `FILE_DIRECTORY_FILE`, so it always takes the
denied row. The enumerate-only policy (value 6) has its own mask in
`BfsCheckAndApplyPolicy` (`0xFFEDFF76`, allowed `0x00120089`), also without
0x20, which is why `cd` into an enumerate-only ancestor fails too. Verdict: a
one-constant bug (the directory mask should be `0xFFE1FF5E`), not a policy;
traverse grants nothing that the already-allowed listing does not, and the
contained token even holds `SeChangeNotifyPrivilege`.

### 4.9.2 Where the per-file cost goes

Measured on the 2-vCPU debug VM with `nttest openloop` (open + read 1 byte +
close of 1 000 files, in a loop) inside an environment, and WPR CPU sampling
(1 kHz, kernel and user, stacks) dumped with `tracerpt` and symbolized
through the kernel debugger (`psec/experiments/kernel/`). Two separate costs:

**A. Creating the environment: ~1 ms per granted path, in the broker.**

| grants | `CreateProcessSecurityEnvironment` | 
|---|---|
| 1 directory | 40 ms |
| 1 000 files | 1 091 ms |
| 4 000 files | 3 807 ms |

The caller's process barely works (477 samples); the time is CPU in
`svchost.exe -k netsvcs -p -s Appinfo` (3 601 samples = 3.6 s for 4 000
paths), the AppInfo service that `processmodel.dll` reaches over `ncalrpc`
(the plan's `AppInfoSandboxLaunch` endpoint). Inclusive profile of that
service during the creation: `nt!NtOpenFile` 23 %, `nt!NtClose` 23 %,
`nt!NtDeviceIoControlFile` 18.5 % (of which `bfs!BfsProcessSetPolicyRequest`
11 %), `nt!NtCreateFile` 12 %, `nt!NtQueryFullAttributesFile` 5 %,
`ntfs!NtfsCommonCreate` 9 %. So per path the service opens the target
(twice, once as a file, once through `NtCreateFile`), stats it, closes it,
and then issues the set-policy IOCTL; `bfs.sys` itself is a tenth of the
work. Inside the IOCTL the policy is **written to disk**: a breakpoint pair on
`bfs!BfsProcessSetPolicyRequest` and `bfs!BfsWriteBlock` during a 100-path
creation stops 1 : 11 in the first dozen hits, i.e. every path insert ends in
several `ZwWriteFile`s of 16 KB blocks to the file-backed policy store
(`BfsCreateStorage` / `BfsAddOrModifyEntry`); the `BfsInMemoryPolicies`
feature that would skip this is not active on this build. Nothing here is
per-open state: it is paid once per environment, which is why pooling and
directory grants (section 0, the JNI branch) remove it.

**B. Every open inside the environment: +170 µs, in the opener's thread,
independent of policy size.**

| policy | µs per open (2-vCPU VM, no profiler) | opener CPU for 30 000 opens (profiled) |
|---|---|---|
| none (plain process) | 111 | 4.7 s |
| 1 directory grant | 280 | 12.1 s |
| 1 000 file grants | 303 | 12.8 s |
| 4 000 file grants | 332 | — |

The policy lookup itself is cheap (`bfs!BfsGetPolicy` + `BfsFindEntry` ≈ 5 %
of the opener's CPU, hash-table per path component, hence the small growth
with 4 000 entries). The tax is what `BfsPreCreateOperation` makes the
kernel do for each create, inclusive of the opener's CPU under the
environment vs without:

| work per create | sandboxed | plain |
|---|---|---|
| `bfs!BfsPreCreateOperation` (all of the filter's work) | 53 % | 1 % |
| `fltmgr!FltGetFileNameInformation` (normalized name) → `luafv!LuafvGenerateFileName` 19.6 %, `fltmgr!FltpExpandFilePathWorker` 11 % (parent-directory walk, `NtQueryDirectoryFile` 4 %) | 33 % | 0.8 % |
| `bfs!BfsIsApplicableToken` → `nt!RtlCheckTokenCapability` | 11 % / 7 % | 0.5 % |
| `bfs!BfsApplyPolicyAsUser` → `nt!NtDuplicateToken` 4.3 %, `ObOpenObjectByPointer` 2 % | 7 % | 0 |
| `nt!ExAllocatePool2` (name buffers, contexts, token copies) | 7 % | 3 % |

In absolute terms the environment adds about 8 s of opener CPU per 30 000
opens: roughly half is the normalized-name query that `bfs.sys` issues on
every create (and which the LUA virtualization filter above it answers by
generating the name and walking parent directories), a tenth the capability
check of the AppContainer token, a tenth the token duplication and
attribute rewrite that lets the open proceed as the medium-integrity user,
the rest allocation and the second pass through the filter stack. None of
it depends on how many paths the policy holds, which is the measured fact
behind "precise mode is only 1 % slower than the adapter and 55 % slower
than local" in the JNI branch: the per-file policy costs at creation, the
per-open mediation costs the same under any policy. What would shrink B is
Microsoft's: caching the normalized name on the stream context instead of
querying it per create, skipping the capability check when the policy
decision does not need it, and not duplicating a token per open (one
impersonation token per environment would do).

## 5. Fixes, by class

**c, in the exe (done on this branch):** `cmd.exe` argv verbatim; runfiles
directories read-write; `TMPDIR`; `USERPROFILE`/`LOCALAPPDATA`; output
widening; symlink-target grants; enumerate-only ancestors; `@params`.

**b, Bazel:**
1. Pass the shell's directory and the toolchain roots as read-only grants
   (`-r`), from `--shell_executable` and a new repeatable
   `--experimental_windows_sandbox_readonly_root` (gaps 11, 12).
2. Pass the runfiles directory of tests as writable (gap 5) and
   `requires-network` as a new `-N` (gap 10).
3. `cmd_ps`: `-ExecutionPolicy Bypass` instead of `Set-ExecutionPolicy`
   (gap 4). `tools/osx/BUILD`: no `local = 1` on Windows (gap 2).
4. Sandboxed workers on Windows (gap 14): the only item that costs days.

**d, toolchain:**
1. MSYS runtime patch for AppContainers (gap 1), the one change that makes
   `Genrule`, `ProtocAuthenticityCheck`, `sh_binary` and `sh_test` run
   unchanged.
2. Until then: busybox-w32 with a `longPathAware` manifest and
   `LongPathsEnabled`, a native `zip.exe` next to it, and the two scripts
   that need bash proper (`minimize_jdk.sh`, `generate_jvm_module_options.sh`
   works) kept on git-bash locally (gap 13).
3. Developer Mode on build machines (gap 7); relocatable tool binaries
   (gap 8).

**a, Microsoft:** `FILE_TRAVERSE` on read-only grants; a non-AppContainer
identity (or an AppContainer-aware `\BaseNamedObjects`); junctions and hard
links in read-write grants; USER32 from session 0.

## 6. Shortest path to 100 %

Today 4 768 of the 6 244 actions (every spawn except 138 bash ones) run in
a security environment through the native exe, and the build succeeds. The
remaining 138 spawns are bash, and they all hinge on one thing: a shell that
starts inside an AppContainer.

1. **Now, without touching Bazel or Windows (hours, done here):** busybox-w32
   as the shell for genrules *and* for the sh toolchain
   (`--shell_executable=…\bash.exe --repo_env=BAZEL_SH=…\bash.exe`, a
   `longPathAware` busybox, a native `zip.exe` next to it, the shell
   directory in the read-only roots, the trampoline, every knob through
   `--action_env` and `--host_action_env`). Result: **4 897 of 4 900
   spawns sandboxed**, the build runs to 6 238 of 6 244 actions in 2 944 s
   on the box (4 % more than with the 138 bash actions local). What is
   left: `minimize_jdk.sh` (needs bash's `source … ||` semantics, 4.8),
   protobuf's `ProtocAuthenticityCheck` (no `use_default_shell_env`, so no
   grants reach it; one line in `protoc_authenticity.bzl` or the runner
   flags of item 3), and the `local = 1` genrule. Each is a one-line change
   in the tree or in the rule; until then `--strategy=<mnemonic>=local` for
   exactly those.
2. **The real fix (days, in the toolchain):** the MSYS runtime made
   AppContainer-aware (section 4.1), so git-bash, `sh_binary`, `sh_test` and
   every `cmd` genrule run unchanged. This is a contained change to
   `winsup/cygwin` and does not need Bazel or Windows changes; it needs Git
   for Windows (or MSYS2) to ship it.
3. **Bazel side (hours each, independent of 1 and 2):** read-only roots and
   the shell directory as `-r`, runfiles directory writable, per-action
   temp, `requires-network`, and the `cmd_ps` prologue.
4. **Not needed for Bazel's own build, but for "every action anywhere":**
   sandboxed workers (days), and from Microsoft: `FILE_TRAVERSE` on
   read-only grants, junctions/hard links in read-write grants, a
   non-AppContainer identity, USER32 from session 0.

What remains Microsoft's to change after 1-3 are done: nothing that blocks
Bazel's own build. The three OS behaviours that cost workarounds are the
`FILE_TRAVERSE` denial (worked around by the runfiles grant, but any action
that `cd`s into a read-only directory still fails), the AppContainer
identity (the reason MSYS needs a patch at all; it also stripes the symlink
privilege and redirects `TEMP`), and the session-0 restriction on USER32.

## 7. Experiments (reproducible)

Everything lives in `psec/experiments/`; the probe tools build with the
`build-*.cmd` next to them (VS 2022 Build Tools). Paths assume the VM layout
(`C:\mxc\psecexe\…`, Bazel tree in `C:\mxc\bazel-src`, host
`C:\mxc\bin\bazel-patched.exe`, `JAVA_HOME=C:\mxc\jdk`). Anything that runs a
USER32 importer inside an environment must run from the console session:
`task.cmd <name> <script>` creates and starts a scheduled task with `/it`,
`it.cmd` is the wrapper that captures the output.

| experiment | script | what it shows |
|---|---|---|
| exe smoke test (grants, denial, exit code, env, network allow/deny, `@params`) | `smoke.cmd` | section 2 |
| example workspace (`example/`) through the native exe | `ex.cmd` (= `example/run.cmd` with explicit host and output root) | positive build, 4 denials, write contained, 40-genrule overhead |
| git-bash / busybox inside an environment | `bash1.cmd` | `NtCreateDirectoryObject(\BaseNamedObjects\msys-…): 0xC0000022`; busybox runs |
| object directory DACLs; pre-created MSYS directories; bash's next failure | `bnodir.cpp`, `bash2.cmd` | section 4.1 |
| Process Monitor trace of bash (`/BackingFile`, `/SaveAs` csv) | `procmon1.cmd` | the `\Device\NamedPipe\LOCAL\msys-…-sigwait` `ACCESS DENIED` |
| token, mitigations, pipes/events/sections, `chdir`, open modes, links | `nttest.cpp`, `nt1.cmd`, `nt2.cmd`, `nt3.cmd` | sections 2, 4.2, 4.3, 4.4 |
| PowerShell with Bazel's `cmd_ps` prologue | `ps2.cmd`, `pipe1.cmd`, `pipetest.ps1` | section 4.5 |
| `cmd.exe` argument passing (the `@zlib` genrule shape) | `q.cmd` | gap 3 |
| busybox vs the tree's bash constructs; long paths; native zip | `bbsyntax.cmd`, `bblong.cmd` + `bb.manifest`, `build-zip3.cmd` | gap 13 |
| `bazel test` of `psectests/` (cc, java, py, sh), sandboxed with git-bash, with busybox, and local | `tests.cmd`, `psectests/` | gap 5, section 0 |
| full builds of `//src:bazel-dev.exe` | `bb.cmd` + `bb-exe1.cmd` (today's exclusions, box), `bb-exe2.cmd` (no exclusions, git-bash), `bb-exe4.cmd`/`bb-exe5.cmd` (no exclusions, busybox), `bb-exe3.cmd` (box, busybox) | section 0 |

The flags of the all-sandboxed configuration, for reference:

```
bazel build //src:bazel-dev.exe --keep_going --jobs=8 ^
  --experimental_use_windows_sandbox=yes ^
  --experimental_windows_sandbox_path=C:\mxc\psecexe\BazelSandbox.exe ^
  --spawn_strategy=windows-sandbox ^
  --shell_executable=C:\mxc\psecexe\tools\bash.exe ^
  "--action_env=BAZEL_MXC_EXTRA_RO=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools;C:\Program Files (x86)\Windows Kits;C:\mxc\psecexe\tools" ^
  --action_env=BAZEL_MXC_DIR_GRANTS=1 ^
  --action_env=BAZEL_PSEC_LOG=C:\mxc\log\psecexe-actions.log
```

(`tools\bash.exe` is busybox-w32 1.37 `busybox64.exe` with a `longPathAware`
manifest merged in by `mt.exe`, `tools\zip.exe` the Info-ZIP 3.0 build of
`build-zip3.cmd`; `LongPathsEnabled = 1` in
`HKLM\SYSTEM\CurrentControlSet\Control\FileSystem`.)
