# `BazelSandbox.cpp` — a native Win32 implementation of Bazel's Windows sandbox on PSEC

**Goal.** A single-file C++17/20 program that implements the contract Bazel's
`WindowsSandboxedSpawnRunner` emits (the same contract the Rust `mxc-sdk`
adapter implements), but calling the Windows **Process Security Environment**
("PSEC") API in `processmodel.dll` *directly*, with **no MXC SDK**. The point is
to establish the floor on Windows sandboxing overhead for Bazel and to find out
which costs are inherent to the OS versus added by the SDK.

**Boundary rule honoured.** We call exported DLL functions only
(`processmodel.dll` PSEC exports, `kernel32`/`KernelBase` `CreateProcessW` +
`*ProcThreadAttribute*`, `kernel32` job objects). We do **not** issue raw
`ntdll` `Nt*`/`Zw*` syscalls. `processmodel.dll` itself does the `ntdll` and
kernel-filter work on our behalf, which is exactly what we want to measure.

**Status of the evidence.** Everything in §1–§2 marked *[evidence]* was read off
this machine: `dumpbin /exports` and `llvm-readobj --coff-imports` of
`C:\Windows\System32\processmodel.dll` (10.0.26100.9549), the public + private
symbols from the matching `processmodel.pdb` (downloaded from
msdl.microsoft.com, GUID `BC038084-66E1-CBE9-DBFF-DE3163A15388`, age 1), the
DLL's embedded strings, the Windows 11 25H2 26200.9550 SDK headers, the vendored
FlatBuffers schema `ProcessSecurityEnvironment.fbs` from
`github.com/microsoft/mxc`, and a purpose-built C++ probe (`native/probe.cpp`)
run on the throwaway VM. Items marked *[inference]* are reasoned from that
evidence; I call them out so an implementer knows what still needs confirming.

---

## 0. TL;DR of the new findings

- **The spec is a FlatBuffer**, root table `ProcessSecurityEnvironment`, file
  identifier `"PSEC"`, schema version 1.1 on this build. The exact `.fbs` is
  vendored in the MXC repo and originates from the Windows OS tree (validated
  build 10.0.26690). We can build the blob in-process with the generated
  `flatc` header and nothing else. *[evidence]*
- **`CreateProcessSecurityEnvironment` is almost entirely in-process user-mode
  work in `processmodel.dll`**, talking to the `bfs.sys` filesystem filter
  driver, the WFP firewall (`fwpuclnt`), AppContainer profile APIs (`USERENV`),
  and job/token APIs — all via *exported* functions, no broker RPC on the basic
  path. *[evidence for the imports; inference that the basic path is broker-free]*
- **Raw cost, measured, no SDK:** `CreateProcessSecurityEnvironment` is
  **~28 ms fixed + ~0.95 ms per read-only path**, linear and clean to 5 000
  paths (n=1→28 ms, 100→125 ms, 1000→985 ms, 2000→1920 ms, 5000→4780 ms).
  *[evidence — probe]*
- **An environment handle can be reused across many `CreateProcessW` calls.**
  Attaching a prebuilt handle and running `cmd /c exit 0` costs **~59 ms per
  launch, independent of policy size** (58 ms at 100 paths, 59 ms at 2000). The
  entire per-path cost is paid once at `Create`, not per spawn. *[evidence — probe]*
- **Therefore the big lever is policy reuse.** A per-build or per-toolchain
  environment with a fixed coarse policy collapses the dominant cost. The floor
  for a contained trivial action with a *reused* environment is ~59 ms (vs
  ~22–27 ms bare `cmd`), i.e. ~32 ms of containment tax per spawn plus the
  in-container file-mediation slowdown of the action itself.
- **The SDK adds very little to `Create`/`CreateProcessW` themselves.** The
  README's "0.2 s + 6.5 ms/grant under Bazel" is per-path OS cost (≈1 ms/path
  standalone, inflated to ~5.5 ms under 16-way contention + enumerate-ancestors)
  plus `wxc-exec`/JSON-parse hops the in-process path already removes. A native
  binary's remaining wins are reuse, directory grants, and dropping per-action
  process/thread spin-up — not shaving the Microsoft code.

---

## 1. Anatomy of the primitive (from symbols, headers, imports)

### 1.1 Exported API surface relevant to PSEC *[evidence: `dumpbin /exports`]*

`processmodel.dll` (10.0.26100.9549, 25 exports) exposes two families. The
**flat PSEC** family is the one we use:

```
CreateProcessSecurityEnvironment
CloseProcessSecurityEnvironment
CancelProcessSecurityEnvironmentTerminateOnClose
QueryProcessSecurityEnvironmentSupport
IsProcessSecurityEnvironmentVersionSupported
CreateProcessAsUserInsideSecurityEnvironment
```

plus an **`Sbe*` ("Sandbox Engine") family** that is the lower internal layer
(`SbeCreateProcessSecurityEnvironment`, `SbeCreateProcessAsUserInSandbox`,
`SbeCreateProcessAsUserInSandboxWithPolicyRulesEnforcement`,
`SbeDetachProcessSecurityEnvironment`, `SbeGetSecurityEnvironmentAppContainerSid`,
`SbeBrokerSandboxedCreateProcess`, `SbeCreateProcessHooks_*`), a **broker**
entry (`BrokerSandboxedCreateProcess`), and an **`Experimental_*`** family that
takes a *compiled* spec (`Experimental_CompileSandboxSpecificationInternal`,
`Experimental_CreateProcessInSandbox`, `Experimental_FreeSandboxSpecification`,
`Experimental_QuerySandboxSupport`) using the older `SandboxTechSpecLayout`
("SBOX") format. The flat exports wrap `Sbe*`: the PDB shows
`CreateProcessSecurityEnvironment` → `SbeCreateProcessSecurityEnvironment` →
`SbepCreateSandbox`, and `CreateProcessAsUserInsideSecurityEnvironment` →
`SbeCreateProcessAsUserInsideSecurityEnvironment` → `SbepCreateProcessInsideSandbox`.
*[evidence: private S_LPROC32 symbols]*

Signatures (headers were searched first — the API is **not** declared in the
26100 SDK `um`/`shared` headers; `ProcThreadAttributeSecurityEnvironment` is not
in `WinBase.h`'s attribute enum either, which stops at `SveVectorLength`=30. So
these come from the MXC `secenv.rs` FFI, corroborated by the PDB demangled
types): *[evidence: PDB + secenv.rs; the SDK headers do NOT declare it — a native build must declare it itself]*

```c
// processmodel.dll, __stdcall (extern "system"); HPROCESS_SECURITY_ENVIRONMENT is a HANDLE.
HRESULT CreateProcessSecurityEnvironment(
    const void*  sandboxSpecification,      // "PSEC" FlatBuffer
    DWORD        sandboxSpecificationSize,
    DWORD        flags,                      // PROCESS_SECURITY_ENVIRONMENT_FLAGS (int-sized)
    HANDLE*      processSecurityEnvironment);// out
HRESULT QueryProcessSecurityEnvironmentSupport(UINT64* supportFlags);
HRESULT IsProcessSecurityEnvironmentVersionSupported(DWORD major, BYTE* available, DWORD* minor);
void    CloseProcessSecurityEnvironment(HANDLE processSecurityEnvironment);
void    CancelProcessSecurityEnvironmentTerminateOnClose(HANDLE processSecurityEnvironment);
```

- **Support flags (`QueryProcessSecurityEnvironmentSupport`)** — measured on this
  box: `0x000000000000000F`. Known bits (from `secenv.rs`): `0x1` FileSystemDeny,
  `0x4` FileSystemEnumerate, `0x8` NetworkIngress; `0x2` is observed set but
  unnamed in the SDK (almost certainly the base filesystem read/write grant, or
  network-egress). `IsProcessSecurityEnvironmentVersionSupported(1,…)` returns
  available=1, **minor=1** → contract **1.1**. *[evidence — probe output]*
- **`flags`**: MXC always passes `0`. A "terminate-on-close" bit exists (hence
  `CancelProcessSecurityEnvironmentTerminateOnClose`), so the environment handle
  can be configured to kill its process tree when closed; MXC chooses explicit
  teardown and a job object instead. We do the same. *[evidence: secenv.rs comment + export name]*

### 1.2 Attaching the environment to a process *[evidence: secenv.rs + SDK headers]*

The handle is attached via a process/thread attribute on a normal
`CreateProcessW`:

```c
#define ProcThreadAttributeSecurityEnvironment 35
#define PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT (35 | PROC_THREAD_ATTRIBUTE_INPUT) // 35 | 0x00020000
```

`InitializeProcThreadAttributeList`/`UpdateProcThreadAttribute` carry the
`HANDLE` by value; optionally a second attribute `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
restricts inherited handles (used only when piping stdio). `CreateProcessW` is
called with `EXTENDED_STARTUPINFO_PRESENT`. `KernelBase.dll` recognises the
attribute — its strings include `BasepCreateProcessAsUserInsideSecurityEnvironment`
and it imports the PSEC exports from the `api-win-appmodel-processmodel`
API set — so the launch is routed through the security environment *inside
`CreateProcessW`*, not by us calling the `*InsideSecurityEnvironment` export
directly. *[evidence: KernelBase strings/imports; inference that the attribute is what triggers routing]*

**Inheritance / lifetime.** The environment applies to the whole process tree
(children inherit it; this is a kernel-enforced per-process-tree policy, matching
the README's "deny-by-default path policy applied to the whole process tree").
`CloseProcessSecurityEnvironment` releases the server-side state. MXC keeps the
handle alive until the child has exited and been reaped, then closes it; it also
puts the child in a `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` job so an abandoned
sandbox dies. We keep the same ordering. The reuse probe shows the handle stays
valid and reusable across many sequential `CreateProcessW` calls, so lifetime is
tied to `Close`, not to any one child. *[evidence — probe; secenv.rs/base_container_runner.rs]*

### 1.3 What `CreateProcessSecurityEnvironment` touches in user mode

From `llvm-readobj --coff-imports` of `processmodel.dll` and the PDB's private
symbols, the create path assembles the sandbox from these OS facilities, **all
reached through exported functions in-process** *[evidence: imports + symbols]*:

| Facility | Imports seen | Private symbols | Role (inference) |
|---|---|---|---|
| **AppContainer profile/SID** | `USERENV!CreateAppContainerProfile`, `DeleteAppContainerProfile`, `DeriveAppContainerSidFromAppContainerName`; `KERNELBASE!CreateAppContainerToken`, `DeriveCapabilitySidsFromName` | `ApplyAppContainer`, `DerivePackageCapabilitySid`, `AddCapability`, `CloseSecurityCapabilities`, `BuildContainerId` | Each environment is backed by an AppContainer named `Sandbox.{guid}` (string `Sandbox.%s`); profile + `AC\Temp` folder created here. Explains `TEMP`/`LOCALAPPDATA` rewrite to `…\Packages\sandbox.{guid}\AC\Temp`. |
| **Brokering File System (BFS)** | `FLTLIB!FilterAttachAtAltitude`/`FilterDetach`/`FilterVolumeInstanceFind*`; `ntdll!NtDeviceIoControlFile`; `GetFinalPathNameByHandleW`, `GetVolumePathNameW`, `GetVolumeInformationW` | `SandboxFilesystem::{ApplyFilesystemPolicy,EnsureBfsAttachedForPaths,EnsureBfsAttachedToVolume,AttachBfsToVolume,DetachIfUnused}` | **The per-path cost lives here.** `bfs.sys` (altitude 150000, "Brokering File System") is programmed with one policy entry per granted path. Strings: `\\.\GLOBALROOT\Device\Bfs`, `BfsAddPolicy`. |
| **WFP network filters** | `fwpuclnt!Fwpm{EngineOpen0,FilterAdd0,SubLayerAdd0,ProviderAdd0,Transaction*}`; `FirewallAPI!NetworkIsolation*LoopbackRules` (delay-load); `WS2_32!InetPtonW`; `ntdll!RtlIpv4/6StringToAddressW` | `Tessera::Networking::{NetworkFilterManager,OpenSandboxWfpEngine,AddPolicyFilters}`, `ApplyNetworkPolicies`, `ApplyLoopbackRule` | Egress/ingress policy = WFP filters keyed on the AppContainer package SID (`FWPM_CONDITION_ALE_PACKAGE_ID`/`ALE_USER_ID`). GUIDs/names "Tessera Sandbox Provider/Filter/SubLayer". |
| **Job object / UI** | `api-ms-win-core-job!{CreateJobObjectW,SetInformationJobObject(implied),AssignProcessToJobObject,TerminateJobObject,QueryInformationJobObject,IsProcessInJob}`; `TpAllocJobNotification` | `CreateSandboxJob`, `ApplyUILimits`, `SetUILimitsOnJob` | Job UI limits (`JOB_OBJECT_UILIMIT_*`) + Win32k mitigation. |
| **Token** | `security-base!{DuplicateTokenEx,SetTokenInformation,GetTokenInformation,AccessCheck,ImpersonateLoggedOnUser}`; `ntdll!{NtDuplicateToken,NtSetInformationToken}` | `GetTokenIntegrityLevel`, `GetTokenUserSid`, `ApplyIntegrityLevel`, `ApplyLeastPrivilege` | Builds the AppContainer token the child runs under. |
| **Spec parse/validate** | FlatBuffers `Verify*` in PDB | `ParseProcessSecurityEnvironmentSpec`, `EnforceCreateProcessPolicy`, `EvaluateCreateProcessPolicy`, `CpPolicy::*` | Parses + verifies the `"PSEC"` buffer; `CpPolicy` is a separate "create-process policy"/agent-governance layer. |
| **Registry / agent governance** | `RegGetValueW` | `QueryCallerAgentIdentity`, `TagKnownAgenticCaller`, `IsDeveloperBypassActive` | Reads `SOFTWARE\Microsoft\AgentGovernance\KnownAgentIds`, `…\AppModelUnlock`. Classifies the *caller* (e.g. agentic apps); not on the hot path for us. |
| **RPC (`ncalrpc`)** | `RPCRT4!{RpcStringBindingComposeW,RpcBindingFromStringBindingW,NdrClientCall3,Ndr64AsyncClientCall}`; string `ncalrpc`, `AppInfoSandboxLaunch` | `SandboxConnectionManager`, `AicpAsync*` | A client RPC interface to the **AppInfo** service (`appinfo.dll` exports `AiEnableDesktopRpcInterface`; its `launch_sandbox.cxx` calls the `Sbe*` exports). *Inference:* the ncalrpc/`Broker…` path is for elevated/MSIX/desktop-broker launches; the basic `CreateProcessSecurityEnvironment` + `CreateProcessW` we use does **not** round-trip to a service (consistent with the measured per-path cost scaling with BFS `NtDeviceIoControlFile`, not RPC). This is the one thing most worth confirming with a kernel/ETW trace. |

**So: `processmodel.dll` does not "merely marshal to a kernel/broker component."**
On the basic path it *is* the broker — it compiles the FlatBuffer and programs
`bfs.sys` (kernel filter), WFP, the AppContainer profile/token, and a job object
itself, from the caller's process. The only kernel component with a per-path
relationship is **`bfs.sys`** (one IOCTL per path). *[evidence for mechanisms; inference for "basic path is in-proc"]*

### 1.4 The specification blob — `ProcessSecurityEnvironment.fbs` *[evidence]*

FlatBuffer, `namespace ProcessSecurityEnvironmentLayout`, `file_identifier "PSEC"`,
`root_type ProcessSecurityEnvironment`. Vendored in MXC from the Windows OS repo
(provenance: validated build 10.0.26690, schema SHA-256
`736cacef…`, generated with `flatc` **25.12.19** pinned). This is the "CPSE"
wire format; the legacy "CPIS"/`Experimental_*` path uses a different `SandboxSpec.fbs`
("SBOX"). Full root table:

```fbs
struct SchemaVersion { major:uint16; minor:uint16; }            // stored inline in the table

table ProcessSecurityEnvironment {
  version:SchemaVersion (required);     // slot 0  — 1.0 initial, 1.1 current
  capabilities:string;                  // slot 1  — CSV: "internetClient,privateNetworkClientServer,networkLoopback,…"
  disallow_win32k_system_calls:bool = false; // slot 2 — Win32k lockdown (ui.disable)
  ui_restrictions:uint64 = 0;           // slot 3  — JOB_OBJECT_UILIMIT_* bitmask
  fs_read_write:[string];               // slot 4
  fs_read_only:[string];                // slot 5
  fs_deny:[string];                     // slot 6
  network_policy:NetworkPolicy;         // slot 7
  fs_enumerate:[string];                // slot 8  — [version 1.1] enumerate/query-only
}
table NetworkPolicy { proxy:ProxyInfo; egress:EndpointPolicy; allowed_appcontainer_peer:string; ingress:IngressPolicy; }
enum FilterAction:byte { deny, allow }
enum IpProtocol:byte { any, tcp, udp, icmpv4, icmpv6 }
table EndpointPolicy { default_action:FilterAction = deny; allow:[EndpointRule]; deny:[EndpointRule]; }
table IngressPolicy  { default_action:FilterAction = deny; host_loopback:FilterAction = deny; }
table EndpointRule   { destinations:[DestinationRule]; ports:[PortRule]; }
table DestinationRule{ subnet:IpSubnet; except:[IpSubnet]; }
table IpSubnet       { address:string; prefix_length:ubyte = 0; }
table PortRule       { protocol:IpProtocol = any; port:uint16 = 0; end_port:uint16 = 0; }
table ProxyInfo      { url:string; }
```

Field semantics (read-only / read-write / denied / enumerate-only; network;
UI/Win32k) map 1:1 onto the Bazel contract. The spec is thus a **versioned
FlatBuffer**, not an opaque versioned C struct. Evolution is FlatBuffers' normal
add-at-end/slot-stable scheme; `version` is both a required field and a
compatibility gate checked by `IsProcessSecurityEnvironmentVersionSupported`.

For a native build we embed a `flatc`-generated header (see §3) — but note we
only ever *write* this buffer, with a handful of fields, so even a ~120-line
hand-rolled FlatBuffers writer would do and removes the last third-party
dependency. The `"PSEC"` identifier is the 4 bytes at offset 4 of the finished
buffer.

---

## 2. Cost model (what the 150 ms and the per-path cost are, measured)

### 2.1 Raw-API numbers from the probe (`native/probe.cpp`, this VM, 8 vCPU, single-threaded)

`CreateProcessSecurityEnvironment` alone, PSEC 1.1 spec (version + deny egress +
N read-only paths, no enumerate), median of 5 after a warm-up, paths synthetic
(non-existent under an existing base dir):

| N read-only paths | spec size | Create time |
|---:|---:|---:|
| 1 | 128 B | **28 ms** |
| 100 | 4.4 KB | **125 ms** |
| 1 000 | 44 KB | **985 ms** |
| 2 000 | 88 KB | **1 920 ms** |
| 5 000 | 220 KB | **4 780 ms** |

Least squares: **≈ 27 ms + 0.95 ms/path**, R²≈1.0. *[evidence]*

`CreateProcessW` with the attribute attached, reusing one prebuilt environment,
running `C:\Windows\System32\cmd.exe /c exit 0` and waiting:

| policy size | reuse: per-launch | fresh env per launch (create+launch) |
|---:|---:|---:|
| 100 paths | **58 ms** | 184 ms |
| 2 000 paths | **59 ms** | 1 995 ms |

*[evidence]* The per-launch number is **flat in policy size** — the whole
per-path cost is in `Create`. Bare `cmd /c exit 0` is ~22–27 ms (README), so
attach + BFS-mediated process start adds ~32 ms.

Two facts worth flagging:
- **`Create` succeeds for paths that do not exist** (all 5 000 synthetic paths
  were missing; `hr=S_OK`). So the per-path work is *policy-entry registration*
  in BFS, not a per-file `stat`/ACL walk. This is why the SDK widens output
  grants to the parent directory (a grant on a missing file registers but the
  file still can't be created — the *directory* must be granted) and why
  directory grants are so much cheaper (fewer entries), not cheaper per entry.
- The numbers are single-threaded. Under Bazel's 16-way parallelism the README's
  standalone ~1 ms/path rises to ~5.5 ms/path including enumerate ancestors —
  that gap is (a) BFS driver contention across concurrent `Create`s and (b) the
  extra enumerate-only ancestor entries (one chain per grant). Both are OS cost,
  not SDK.

### 2.2 Where each cost comes from, and whether a native build can avoid it

| Cost | ms (approx) | Where | Avoidable natively? |
|---|---|---|---|
| Fixed per `Create` | ~27 ms | AppContainer profile create (`Sandbox.{guid}`, `AC\Temp`), token build, WFP sublayer/filters, job, FlatBuffer parse+verify | **Only by reuse.** Inherent to one environment. Amortised to ~0 if one environment serves many actions. |
| Per read/rw/enumerate path | ~0.95 ms | One BFS policy-entry IOCTL to `bfs.sys` per path | **Reduce the count**: directory grants, prune nested paths, drop enumerate when a grant covers the ancestor. Can't make an individual entry cheaper (kernel round-trip). |
| `CreateProcessW` + attach | ~32 ms over bare | KernelBase routes through the security environment; AppContainer token applied; child starts under BFS mediation | Inherent per spawn. |
| In-container action slowdown | cl.exe ~2×, javac ~1.3× | Every file open in the child is mediated by `bfs.sys` | Inherent; coarser grants don't change it (mediation is per *access*, not per policy entry). |
| `wxc-exec.exe` hop + JSON parse | ~25 ms + parse | SDK CLI only | **Already gone** in the in-process Rust adapter; gone in C++ too. |
| SDK bookkeeping (telemetry, learning-mode probing, tier detection, proxy coordinator, `IsApiSetImplemented`, support caching) | small but non-zero per action | `mxc-sdk` | **Removed.** A native binary skips all of it; just `LoadLibraryEx` + 4 `GetProcAddress` once. |

**Conclusion on the 150 ms.** The README's "~148 ms through a real container with
a one-path policy" decomposes (standalone) as roughly: ~27 ms `Create` fixed +
~1 ms policy + ~59 ms `CreateProcessW`+cmd + the `wxc-exec` hop and SDK/JSON work
(~25–60 ms). The native in-process path removes the last bucket, leaving
~**90 ms** for a one-path throwaway environment and ~**60 ms** if the environment
is reused. The Microsoft code (`Create`+`CreateProcessW`) is ~87 ms of that and
is the real floor for a fresh tiny environment; it does not shrink without reuse.

---

## 3. Design of `BazelSandbox.cpp`

Single translation unit, `/std:c++17`, Win32 only, links
`kernel32`/`advapi32`/`user32` (import libs only; PSEC resolved at runtime). One
embedded `flatc`-generated header for the spec (or a hand-rolled writer; see
§3.4). No MXC, no Rust.

### 3.1 Argument parsing — Bazel's contract + `@params`

Bazel's `WindowsSandboxUtil.CommandLineBuilder` emits, in this order:
`-W <cwd>`, `-T <timeout_s>`, `-t <killdelay_s>`, `-l <stdout>`, `-L <stderr>`,
then repeated `-w <rw>`, `-r <ro>`, `-b <deny>`, optional `-D`, then `--` and the
command. `-h` must print usage and exit 0 (Bazel probes the binary with `-h`).
The runner on this branch also writes the `-w/-r/-b` block to a params file and
passes `@<file>` when the command line would exceed ~30 000 chars; the binary
expands `@file` (one arg per line, strip trailing `\r`, skip blanks) **before**
the `--`.

```cpp
struct Args {
  std::wstring cwd, stdoutPath, stderrPath;
  std::optional<DWORD> timeoutMs;              // -T seconds*1000; -t ignored (PSEC has no kill delay)
  std::vector<std::wstring> rw, ro, deny;
  bool debug = false;
  std::vector<std::wstring> cmd;               // argv after --
};
// expandParams(): replace @file args (pre-'--') with the file's lines.
// parseArgs(): flags with a value consume the next token; '--' => rest is cmd.
```

Everything is `wchar_t` end-to-end (paths and the command line are UTF-16; use
`GetCommandLineW`/`CommandLineToArgvW`, or `wmain`).

### 3.2 Policy construction (the bulk of the host-side logic — same rules the Rust adapter had to discover)

Processing order matters because PSEC applies the **most restrictive** intent to
a path listed twice (or under a weaker-intent ancestor). Do it in O(n log n):

1. **Resolve symlink-forest targets.** Bazel's execroot is junctions/symlinks
   into the source tree; `bfs.sys` evaluates on the resolved target. For every
   `-r`/`-w`, add its `GetFinalPathNameByHandleW` target (open with
   `FILE_FLAG_BACKUP_SEMANTICS|OPEN_EXISTING`, `VOLUME_NAME_DOS`, strip the
   `\\?\` prefix, drop UNC targets). Cache by source path — the same toolchain
   junctions recur across thousands of actions, so a process-lifetime
   `unordered_map<wstring,wstring>` of resolved targets is worth it (and the only
   reason the adapter opens each file).
3. **Widen non-existent outputs.** Declared outputs do not exist at action
   start; `Create` registers a grant but the file still can't be created under a
   file-only grant. For each `-w`, if it doesn't exist, grant its parent
   directory instead. (Per-file rw grants on *existing* files do work on .9550.)
4. **Extra read-only roots.** Append `BAZEL_MXC_EXTRA_RO` (`;`-split) — MSVC,
   Windows Kits, JDK, node etc. live outside the execroot and aren't declared
   inputs.
5. **Most-restrictive de-conflict.** A read-only grant must never equal or
   contain a read-write grant, or the output turns read-only ("Permission
   denied" from cl). Drop any `ro` that is or contains an `rw`.
6. **Directory-grant mode** (`BAZEL_MXC_DIR_GRANTS`): replace each read-only
   *file* grant with its parent directory unless that would swallow an `rw`.
   This is the single biggest per-action speedup for input-heavy actions
   (linear per-path cost → one entry per directory).
7. **Dedupe + prune nested.** Lowercase, backslashes, strip trailing separator
   (except drive root). Sort keys; one linear pass drops any path inside the
   previously kept directory. (The adapter notes the old pairwise prune was
   quadratic and dominated large actions.)
8. **Enumerate-only ancestors** (PSEC 1.1 `fs_enumerate`): for every grant and
   the cwd, walk the ancestor chain top-down and add each ancestor *above the
   first grant* as enumerate-only, deduped, unless a grant already covers it
   (covering it would downgrade the grant to enumerate-only). Needed so `dir`,
   `realpath`, and launching an exe from a granted directory work (MXC issues
   1109/1162). Suppress with `BAZEL_MXC_NO_ENUM`.

```cpp
std::wstring key(std::wstring p);              // lower, '\', trimmed
std::optional<std::wstring> finalTarget(const std::wstring& p); // GetFinalPathNameByHandleW, cached
void dedupe(std::vector<std::wstring>&);
void pruneNested(std::vector<std::wstring>&);  // sort keys, single pass
bool coversRw(const std::wstring& dir, const std::vector<std::wstring>& rwKeys);
std::vector<std::wstring> enumerateAncestors(const std::vector<std::wstring>& ro,
                                             const std::vector<std::wstring>& rw,
                                             const std::wstring& cwd);
```

### 3.3 Environment block, UI, network, stdio, timeout, exit

- **Environment.** PSEC needs an explicit block (inheriting the *profile* block
  loses `INCLUDE`/`LIB` for cl). Pass this process's environment verbatim
  (`GetEnvironmentStringsW`). PSEC refuses to launch without `USERPROFILE` and
  `LOCALAPPDATA` present (presence only) — add them from the profile dir if
  Bazel's scrubbed env lacks them. Windows rewrites `TEMP`/`TMP`/`LOCALAPPDATA`
  to the per-container `…\Packages\sandbox.{guid}\AC\Temp` regardless; set
  `TMPDIR` to the `-w` temp dir Bazel granted so Python's `tempfile`
  (owner-only DACL) lands in a granted path rather than the AC\Temp the
  container token can't satisfy. Build with `CREATE_UNICODE_ENVIRONMENT`.
- **UI.** Default `disable_win32k_system_calls = false` and job UI limits that
  allow desktop use (otherwise USER32 importers die with STATUS_DLL_INIT_FAILED).
  `BAZEL_MXC_NO_UI` restores the Win32k lockdown. `ui_restrictions` is the
  `JOB_OBJECT_UILIMIT_*` mask; the job's basic UI restrictions are set with
  `SetInformationJobObject(JobObjectBasicUIRestrictions)`.
- **Network.** `NetworkPolicy{ egress: EndpointPolicy{default_action=deny},
  ingress: IngressPolicy{default_action=deny, host_loopback=deny} }`. Bazel has
  no Windows network flag yet; deny both.
- **Stdio.** Prefer **inherit** (`bInheritHandles=TRUE`, pass the three std
  handles in `STARTUPINFOW` with `STARTF_USESTDHANDLES`, mark them inheritable,
  and list them in `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`). Only create pipes when
  `-l`/`-L` redirect to files or when stdout/stderr aren't console — then pump
  on two threads (inherit the write ends; close them in the parent after
  `CreateProcessW`). This mirrors `base_container_runner.rs`.
- **Timeout / kill.** Create the child `CREATE_SUSPENDED`, assign to a
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` job, `ResumeThread`, then
  `WaitForSingleObject(hProcess, timeoutMs ? timeoutMs : INFINITE)`. On timeout,
  `TerminateJobObject` (whole tree) and exit 124. `-t` kill-delay is accepted
  and ignored (PSEC/job model has no grace timer). Fail closed if the job can't
  be created (don't run an un-killable sandbox).
- **Exit code.** `GetExitCodeProcess` → propagate. Report `CreateProcessW`
  failures with `GetLastError` and a hint (missing required env var → the
  USERPROFILE/LOCALAPPDATA hint; `0xC0000142` → the session-0/USER32 note).
- **argv[0] fix-up.** Resolve a relative, forward-slashed argv[0] against the
  cwd and switch to backslashes (else cmd.exe parses `external/...` `/` as
  switches), exactly as the adapter does.

### 3.4 CreateProcess attribute setup + the two phases (key sketch)

```cpp
// --- declarations the SDK ships but 26100 headers don't ---
#ifndef PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT
#define PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT (35 | 0x00020000) // 35 | PROC_THREAD_ATTRIBUTE_INPUT
#endif
using PFN_Create = HRESULT (WINAPI*)(const void*, DWORD, DWORD, HANDLE*);
using PFN_Close  = void    (WINAPI*)(HANDLE);
using PFN_Ver    = HRESULT (WINAPI*)(DWORD, BYTE*, DWORD*);
using PFN_Query  = HRESULT (WINAPI*)(UINT64*);

// resolve once:
HMODULE h = LoadLibraryExW(L"processmodel.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
auto Create = (PFN_Create)GetProcAddress(h, "CreateProcessSecurityEnvironment");
auto Close  = (PFN_Close) GetProcAddress(h, "CloseProcessSecurityEnvironment");
auto Ver    = (PFN_Ver)   GetProcAddress(h, "IsProcessSecurityEnvironmentVersionSupported");
// fail fast if any is null OR Ver(1,&avail,&minor) says minor<1 (see §3.5).

// Phase 1: build + create the environment.
std::vector<uint8_t> spec = buildPsecSpec(ro, rw, deny, enumPaths, ui, net); // FlatBuffer, id "PSEC"
HANDLE env = nullptr;
HRESULT hr = Create(spec.data(), (DWORD)spec.size(), 0, &env);
if (FAILED(hr) || !env) die("CreateProcessSecurityEnvironment 0x%08X", hr);

// Phase 2: attach + launch.
SIZE_T sz = 0; InitializeProcThreadAttributeList(nullptr, 2, 0, &sz);
auto buf = std::make_unique<BYTE[]>(sz);
auto al = (LPPROC_THREAD_ATTRIBUTE_LIST)buf.get();
InitializeProcThreadAttributeList(al, 2, 0, &sz);
HANDLE envByVal = env;   // stable address, passed by value
UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT, &envByVal, sizeof(envByVal), nullptr, nullptr);
if (inheritStdio)
    UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, stdHandles, 3*sizeof(HANDLE), nullptr, nullptr);
STARTUPINFOEXW si{}; si.StartupInfo.cb = sizeof(si); si.lpAttributeList = al;
si.StartupInfo.dwFlags = STARTF_USESTDHANDLES; si.StartupInfo.hStdInput=hIn; si.StartupInfo.hStdOutput=hOut; si.StartupInfo.hStdError=hErr;
PROCESS_INFORMATION pi{};
BOOL ok = CreateProcessW(nullptr, cmdLine.data(), nullptr, nullptr, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | (pipeMode?CREATE_NO_WINDOW:0),
            envBlock, cwd.c_str(), &si.StartupInfo, &pi);
// assign job (KILL_ON_JOB_CLOSE) -> set UI limits -> ResumeThread -> pump stdio -> wait -> exit code.
// teardown: wait+reap child, TerminateJobObject on timeout, DeleteProcThreadAttributeList, Close(env).
```

### 3.5 Detecting an unsupported OS and failing fast

Before anything: resolve the exports; if `processmodel.dll` is missing or any
export is absent, print a clear message and exit non-zero. Then call
`IsProcessSecurityEnvironmentVersionSupported(1, &available, &minor)`; require
`available && minor >= 1` (1.1 gives `fs_enumerate`, without which the execroot
can't be traversed — see README). Optionally gate specific features on
`QueryProcessSecurityEnvironmentSupport` bits (`0x4` enumerate, `0x8` ingress).
Do **not** attempt the deprecated AppContainer+DACL fallback — on <.9550 per-file
read grants silently don't enforce, which is worse than failing. (`IsApiSetImplemented`
on `api-win-appmodel-processmodel~securityenvironment` is the SDK's gate; a
plain export-presence check is equivalent for us.)

---

## 4. Speed strategy (ranked by payoff)

1. **Reuse one security environment across many spawns.** *Biggest lever by
   far.* The probe shows per-launch cost is flat in policy size when the handle
   is reused (~59 ms) and the whole ~0.95 ms/path cost is paid once at `Create`.
   Two forms:
   - **Per-toolchain environment with a coarse, fixed policy** (grant the MSVC +
     Windows Kits + JDK + execroot roots as *directories*, deny-network, no
     per-input entries). Build it once per toolchain per build, attach it to
     every action using that toolchain. Payoff: eliminates nearly all per-action
     `Create` cost; a 2 000-input Javac action goes from ~2 s of `Create` to
     ~0. **Security cost:** coarser than per-input — an action can read sibling
     inputs it didn't declare (undeclared-read hermeticity is weakened to
     per-directory, not per-file). Acceptable for speed experiments; a
     supportable feature would keep per-input for `--spawn_strategy` correctness
     tests and offer coarse mode behind a flag.
   - **Resident adapter / sandbox server.** Keep `BazelSandbox` alive as a
     persistent process Bazel's runner talks to (like a worker): it holds the
     environment handle(s) and only does `CreateProcessW`+wait per action.
     Removes even the ~25 ms binary start per action and makes environment reuse
     natural. Needs a Bazel-side change (a small request protocol, or reusing
     the worker machinery). Estimated per-action floor: ~**59 ms** + the
     in-container action slowdown.
   - **In-JVM via JNI (no `BazelSandbox.exe` at all).** See §4a — this is the
     logical end state of "reuse + resident": the environment handle lives in
     Bazel's own process and is attached to each action's `CreateProcessW` with
     zero subprocess hops.
2. **Grant inputs by directory (`BAZEL_MXC_DIR_GRANTS`).** Even without reuse,
   collapsing N file grants to a handful of directory grants turns the
   ~0.95 ms/path term into near-constant. README shows +37 % vs +58 % building
   Bazel. Needs a Bazel-side "grant by package directory" option to be done
   safely (don't grant the whole execroot).
3. **Cache resolved symlink targets** process-wide (and across the resident
   server). The only reason to touch each input file is `GetFinalPathNameByHandleW`;
   toolchain junctions recur, so cache hits make policy-build almost free CPU-side
   (the BFS cost remains, addressed by #1/#2).
4. **Drop the enumerate-only ancestor chains when a parent grant already covers
   them.** Each chain is extra ~0.95 ms/entry BFS cost. With directory grants the
   ancestors are usually already covered. The adapter already suppresses covered
   ancestors; verify it's maximal.
5. **Batch / prebuild coarse policies for well-known action classes** (one
   environment for "all CppCompile in this build", keyed by the toolchain + the
   set of directory roots). Requires Bazel to group actions by policy shape.
6. **Micro:** resolve exports once; avoid `IsApiSetImplemented` per action; no
   telemetry/learning-mode; reserve FlatBuffer builder capacity from the
   path count; keep the spec builder allocation-light. Each is small but free.

**Estimated floor.** With a reused per-toolchain environment and directory
grants, a trivial contained action is ~**59 ms** (vs ~22–27 ms bare, ~148 ms
through `wxc-exec`). Real actions add their own in-container file-mediation
slowdown (cl ~2×, javac ~1.3×) which **no adapter change can remove** — it is
`bfs.sys` mediating every file open. That slowdown, not setup, becomes the
dominant Windows-sandbox tax once setup is amortised by reuse.

---

## 4a. Deployment form: per-action exe vs resident server vs Java JNI

First, a correction on the mental model: **there is no per-path handle to
reuse.** `CreateProcessSecurityEnvironment` returns *one* `HANDLE` for the whole
policy (all paths, network, UI). The reusable unit is that **environment
handle**, and the probe proves it can be attached to many `CreateProcessW` calls
at ~59 ms each regardless of how many paths the policy has. So the real question
is *where that handle lives and who calls `CreateProcessW`* — three forms:

| Form | Per-action overhead | Environment reuse | Bazel change | Main cost |
|---|---|---|---|---|
| **A. `BazelSandbox.exe` per action** (what the Rust adapter does, and §3) | exe start (~20–25 ms) + `Create` (~27 ms + 0.95 ms/path) + `CreateProcessW` (~59 ms) | none — fresh env every action | none (drop-in binary) | pays full `Create` every action |
| **B. Resident `BazelSandbox` server** (worker-like) | one IPC round-trip + `CreateProcessW` (~59 ms); `Create` amortised | yes — server caches env handle(s) keyed by policy shape | a request protocol / reuse worker machinery | IPC + handle-cache management |
| **C. In-JVM JNI** | `CreateProcessW` (~59 ms) only; no subprocess, no IPC | yes — handle(s) held in Bazel's heap-side native state | JNI lib + wire the sandbox strategy to it | native code in-process; crash = Bazel crash |

**Would JNI be a better fit? For raw speed, yes — it is the fastest of the three**,
because it removes *both* the `BazelSandbox.exe` launch (form A) *and* the IPC hop
(form B), and makes environment reuse the natural default (the handle just sits in
a `long` field on the Java side). The per-action floor drops to the irreducible
`CreateProcessW`+attach (~59 ms) plus the in-container action slowdown — the same
floor as a perfect resident server, minus the IPC.

But three things make JNI more than a free win, and they're why I'd still
prototype with the standalone exe first:

1. **The JDK won't launch the child for us.** `java.lang.ProcessBuilder`/`Process`
   uses its own native `CreateProcessW` deep in the JVM and gives no way to inject
   a `STARTUPINFOEXW` with `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`. So the
   JNI layer must do the whole launch itself — `CreateProcessW`, stdio pipes/inherit,
   job object, `WaitForSingleObject`, exit-code — and hand Java back a handle/pid it
   can wait on. That's most of §3.3–§3.4 reimplemented behind JNI, i.e. the same
   C++ either way; JNI only changes *who calls it* and removes the process boundary.
   (The existing `WindowsProcesses` JNI in Bazel's `src/main/native/windows` is the
   model and the place this would live.)
2. **Concurrency of a shared handle is unverified.** Reuse was measured
   *sequentially*. Bazel runs ~16 actions in parallel, so a shared per-toolchain
   environment would be attached to many concurrent `CreateProcessW` calls from
   different threads. Needs testing that (a) the handle is safe to use from
   multiple threads at once and (b) the shared AppContainer identity / single
   `AC\Temp` doesn't make concurrent actions collide in temp (it will — see §5).
   The safe middle ground is a **small pool of environments** (one per toolchain
   *and* per in-flight slot, or per unique coarse policy), not one global handle.
3. **Blast radius.** A fault in form A/B kills a subprocess; in form C it kills
   the Bazel server. PSEC is undocumented and we declare its ABI ourselves, so
   in-process is where an ABI mistake hurts most.

**Recommended path:** prototype as the standalone exe (§3) to nail the policy
construction and enforcement against the `neg/` oracle; then, once the behaviour
is proven, promote the same C++ into either a resident server (form B, smaller
Bazel change, keeps the crash boundary) or the `src/main/native/windows` JNI
(form C, fastest). The policy-building and launch code is identical in all three;
the environment-reuse/pooling logic (§4 #1) is what actually delivers the speed,
and it is independent of the deployment form. JNI is the right destination if the
concurrency and identity-collision questions check out.

---

## 5. Risks and unknowns

- **Undocumented, unstable API.** PSEC is **not** in the 26100 SDK headers;
  `ProcThreadAttributeSecurityEnvironment` (35) isn't in `WinBase.h`. We declare
  the signatures ourselves from the MXC FFI + PDB. Microsoft can change the
  export set, the attribute number, the `flags` enum, or the FlatBuffer schema
  between builds (the schema is explicitly versioned for exactly this reason).
  A native binary must gate on `IsProcessSecurityEnvironmentVersionSupported`
  and the support flags and fail fast, never guess.
- **Older builds.** <.9550 (e.g. .9457) select the PSEC tier but can't run a
  real action (no `fs_enumerate`); <.9278 have no PSEC at all and MXC falls back
  to AppContainer+DACL where per-file read grants don't enforce. The native
  binary should refuse rather than silently under-enforce. Build-number gating
  from `bfs`/job-UI features is already a thing MXC does (`os_build_number`).
- **Reuse weakens hermeticity.** A shared coarse environment grants more than any
  single action declared (sibling files in granted directories; MXC applies
  most-restrictive intent only *within* one policy, not across reused ones). Fine
  for a speed floor; for correctness testing keep per-action per-file policies.
  Reusing an environment across actions also shares one AppContainer identity and
  one `AC\Temp` — concurrent actions would collide there, so a resident server
  needs either one environment per in-flight action or per-action temp isolation.
- **The ncalrpc/AppInfo broker question** is the main unknown. If the basic
  `CreateProcessSecurityEnvironment` path *does* round-trip to the AppInfo
  service in some configuration (e.g. non-admin, or when the caller is
  classified as an "agent" by `AgentGovernance`), latency and behaviour could
  differ from the probe (which ran elevated, admin, High IL). Confirm with an
  ETW/WPR trace of a `Create` call, or by running the probe as a standard user.
- **Session 0 / USER32 (MXC #1465).** From an ssh/service session, any contained
  USER32 importer dies with `STATUS_DLL_INIT_FAILED` regardless of UI policy.
  Not a native-binary bug; needs an interactive logon (the probe used `cmd`,
  which doesn't import USER32, to sidestep it). Real CI needs autologon + a
  scheduled task with `/it`.
- **Needs Microsoft input:** junction/symlink *creation* inside the container is
  denied by design (MXC #462 was a junction escape) — runfiles-tree and some
  rules_js actions will fail; MSYS/git-bash dies on its shared `BaseNamedObjects`
  (MXC #1061) so `genrule(cmd=…)`/`sh_*`/`BAZEL_SH` won't run; the enumerate
  semantics (#1109/#1162) and whether coarse enumerate could be made implicit;
  and a documented, header-shipped, stable PSEC contract. The `TEMP` rewrite +
  owner-only-DACL `tempfile` interaction (zipped `py_binary`) is also an OS
  behaviour we can only work around (`TMPDIR`), not fix.
- **FlatBuffers dependency.** Embedding the generated header pins us to a
  compatible FlatBuffers runtime. The schema is tiny and write-only, so a
  hand-rolled ~120-line writer (vtable + the 9 root fields + the small
  NetworkPolicy subtree) removes the dependency entirely and is the recommended
  final form for a single-file binary; the generated header is fine for the
  prototype.

---

## 6. Validation plan

**Functional equivalence with the Rust adapter.**
- Use the example workspace at `C:\mxc\ex2\example` (also `C:\mxc\ex` /
  `scratchpad/ex2.zip`) with its `run.cmd`. Build the C++ binary, point Bazel at
  it with `--experimental_use_windows_sandbox=yes
  --experimental_windows_sandbox_path=…\BazelSandbox.exe
  --spawn_strategy=windows-sandbox` and the same `--action_env` toolchain roots.
- **Positive:** `bazel build //...` of the example — genrule (`cmd_bat`),
  `cl.exe` compile, `link.exe` link — must all succeed sandboxed (README shows
  43 windows-sandbox actions).
- **Negative (the four `neg/` targets, `--keep_going`):** undeclared read →
  "Access is denied"; undeclared write → denied, no file; undeclared tool →
  denied; `curl https://api.github.com` → "Could not resolve host". These are
  the enforcement oracle — a native binary that passes all four enforces the
  same policy the Rust adapter does.
- **Differential test:** run the same action under both binaries with
  `BAZEL_MXC_DEBUG=1`/`-D` and diff the effective policy (rw/ro/deny/enumerate
  lists, UI flag, network). They should be identical after the §3.2 processing;
  any divergence is a bug in the C++ policy construction. Also diff the finished
  FlatBuffer bytes against the SDK's for a handful of real actions (both use the
  same schema + `flatc` pin, so byte-equality is achievable and a strong check).
- Build real Bazel (`//src:bazel-dev`, ~6 200 actions) with the three runner
  changes already on this branch (params file, null inputs, temp cleanup) and
  `--strategy=Genrule=local`, as the README did, to shake out large/odd actions.

**Benchmarking against the Rust adapter.**
- Microbench: reuse `native/probe.cpp` numbers as the raw-API baseline. Add a
  mode that runs a real action class.
- Macrobench: the README's protocol — clean `bazel build //src:bazel-dev`,
  `--jobs=16`, server shut down + `bazel clean` between runs, JSON trace + compact
  exec log + `BAZEL_MXC_TIMING` per-action (prep/spawn/wait ms + grant counts).
  Compare C++ vs Rust adapter vs `local`. Expected: C++ ≈ Rust on per-file
  grants (both bottleneck on OS BFS cost); C++ should win measurably only where
  it removes work the Rust path still does (none, currently — they're on par) or
  where it enables **reuse/resident** mode, which is the hypothesis to test:
  per-toolchain reused environment should move the "create security environment"
  phase (README: median 0.85 s, mean 2.6 s, 9.6k s total/run) toward ~0 and bring
  the whole build close to the `local` wall time plus the in-container action
  slowdown.
- Report per-mnemonic (CppCompile/Javac/Turbine/CppLink), the adapter's own
  prep/spawn/wait split, and a least-squares fit of spawn time vs grant count, to
  confirm the ~27 ms + ~0.95 ms/path model holds inside Bazel and that reuse
  flattens it.

---

### Appendix: artefacts produced for this plan (under `scratchpad/native/`)
- `probe.cpp` + `build-probe.cmd` — the raw-API timing probe (builds clean with
  VS 2022 on the VM; `support`/`create`/`reuse` modes).
- `bin/` — `processmodel.dll`, `appinfo.dll`, `bfs.sys`, `bfscfg.exe`,
  `KernelBase.dll` copied off the VM; `imports.txt`, `strings-*.txt`.
- `pdb/processmodel.pdb` (from msdl) + `publics.txt`, `names.txt`, `procs.txt`.
- `mxc-src/` — the vendored `ProcessSecurityEnvironment.fbs`, its provenance, the
  SDK spec builder (`base_container_helpers.rs`), `job_object.rs`, `api_set.rs`,
  `filesystem_bfs.rs`.
- `flatc/` — pinned `flatc` 25.12.19 + FlatBuffers headers + the generated
  `ProcessSecurityEnvironment_generated.h` (object-API and plain).
(Nothing here is committed.)
