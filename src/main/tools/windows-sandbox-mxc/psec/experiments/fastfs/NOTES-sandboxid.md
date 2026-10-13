# NOTES-sandboxid.md — what the BFS `sandbox` field is, and what the client can do

Target: `processmodel.dll` 10.0.26100.9549 (image base 0x180000000) and
`bfs.sys` (base 0x140000000), both from the psec2 guest (Win11 build 26300.9550,
which ships the same 26100.9549 processmodel.dll). Symbols: PDBs auto-resolved
by IDA / Microsoft symbol server; `usersyms/processmodel.funcs`,
`bfs-funcs.txt`. Live confirmation on psec2 via the WinDbg MCP
(`windbg-psec2`, kdnet), 2026-10-12.

## 1. The call chain, reversed

```text
client process (BazelSandbox.exe)
  CreateProcessSecurityEnvironment(spec, specLen, flags, &handle)   export, RVA 0x11640
  └─ AicCreateProcessSecurityEnvironment                            0x45a4c, Ndr64AsyncClientCall, ncalrpc
     ════════════════════════════════════════════════════ RPC ═══
     appinfo!RAiCreateProcessSecurityEnvironment
     └─ SbeCreateProcessSecurityEnvironment                          0x28320  (srv)
        ├─ ParseProcessSecurityEnvironmentSpec → SandboxTechConfig (v18, 304 bytes)
        └─ SbepCreateSandbox                                         0x22d10
           ├─ name = spec name or "Sandbox." + CoCreateGuid()
           ├─ reject if caller token is already an AppContainer (0x80070005)
           ├─ ApplyAppContainer(&sid, userToken, name)               0x1dc2c
           │    ImpersonateLoggedOnUser(userToken)
           │    CreateAppContainerProfile(name, name, name, 0)       USERENV; 0x800700B7 → DeriveAppContainerSidFromAppContainerName
           │    RevertToSelf()
           ├─ ApplyCapabilities(spec.capabilities @cfg+128)
           ├─ if (any of ro/rw/deny/enumerate non-empty):            ← our lever
           │    CreateAppContainerToken(userToken, &sid, &appToken)  api-ms-win-security-base-private (kernelbase)
           │    SandboxFilesystem::ApplyFilesystemPolicy(            0x35f1c (thin wrapper)
           │      SandboxFilesystem::Instance(),
           │      userToken, appToken, /*flag*/ 0,
           │      ro@cfg+32, rw@cfg+56, deny@cfg+80, enumerate@cfg+104, callerTag)
           │    ├─ SandboxFilesystem::EnsureBfsAttachedForPaths      0x36d30   73 % of the cost
           │    └─ SandboxFilesystem::ApplyFilesystem                0x35be8   20 % of the cost
           ├─ ApplyNetworkPolicies(...) if spec has network / net != 0
           └─ return SandboxInstance (504 bytes, holds sid/appToken/job/...)
        └─ *outHandle = SandboxRegistry::Register(instance)          0x2097c: key into svc-side unordered_map<uint64, shared_ptr<SandboxInstance>>

spawn (client, plain CreateProcessW)
  STARTUPINFOEX attribute 35 | 0x00020000 (PROC_THREAD_ATTRIBUTE_INPUT) = the registered handle
  → kernel resolves it through Appinfo, the child runs with the SandboxInstance's AppContainer token
```

## 2. What the BFS IOCTLs take as `sandbox` — [evidence, live]

`ApplyFilesystem` sends the set-policy request with the input buffer at
`+0x00 = a3` (the third parameter). In `SbepCreateSandbox` the third argument
of `ApplyFilesystemPolicy` is the handle returned by
`CreateAppContainerToken(userToken, appContainerSid)` — **the `sandbox` field
is an AppContainer token handle** (a user-mode handle in the calling process,
here the Appinfo service).

WinDbg confirmation on psec2 (`bp bfs!BfsProcessSetPolicyRequest`, one
`BazelSandbox.exe -r nttest @p100.params` create):

```text
BREAK svchost.exe (3340) at bfs!BfsProcessSetPolicyRequest   ; Appinfo service
rcx ffffe606359ead40 (SystemBuffer), rdx 0x30                ; in-buffer length 0x30
dq @rcx L6:
  +0x00  00000000000001b0   ; sandbox  = token handle 0x1b0 in svchost 3340
  +0x08  0000000200000001   ; +8 type = 1 (file),  +0xC kind = 2 (read-write)
  +0x10  0000000000000002   ; +0x10 flags = 2 (not a root path)
  +0x14  000000000040003e   ; UNICODE_STRING Length = 0x3e, MaxLength = 0x40
  +0x20  0000027a1514a120   ; UNICODE_STRING.Buffer (NT path, user pointer)
  +0x28  0000000000000000   ; unused
bp bfs!BfsIsApplicableToken (called right after):
  rcx = ffffd18c4a4f6060   ; the TOKEN object behind handle 0x1b0
  dt nt!_TOKEN: TokenPrimary, TokenFlags 0x404000, CapabilityCount 1,
     UserAndGroups[0] = S-1-5-21-3695808860-3736537754-1805935027-1002  (the user)
```

`BfsProcessSetPolicyRequest` (bfs.sys RVA 0xbc9c) does
`ObReferenceObjectByHandle(sandbox, 8, SeTokenObjectType, KernelMode, &token)`
and then uses **only**:
- `SeQueryInformationToken(token, TokenUser)` → policy-table key
- `SeQueryInformationToken(token, TokenAppContainerSid)` → stored on each entry
- `BfsIsApplicableToken(token)`: the token must be an AppContainer
  (`TokenAppContainerNumber != 0`; with `Feature_AgenticAppContainerBfsSupport`
  a non-AppContainer token passes if it has the agentic capability — irrelevant
  for us).

## 3. Enforcement matches by SIDs, not by the token object — [evidence]

`BfsCheckAndApplyPolicy` (bfs.sys 0x4170), on every file access by an
AppContainer-token process:

```c
SeQueryInformationToken(Token, TokenUser, &TokenInformation);          // +0x61
SeQueryInformationToken(Token, TokenAppContainerSid, &P);              // +0x79
if (BfsPolicyEntryExists(FltObject, v6, &gBfsPolicyTable,
                         TokenUser, AppContainerSid)) {                // +0x9e..a3
    PolicyEntry = BfsGetPolicyEntry(FltObject, v6, &gBfsPolicyTable, TokenUser);
    ...
    Policy = BfsGetPolicy(entry, &FileNameInformation->Volume,
                          &fileName, agentic ? &AppContainerSid : 0);
```

The policy entries are keyed `{TokenUser SID, AppContainer SID}` — **two
different AppContainer tokens of the same profile (same user + same
AppContainer SID) match the same policies.** This is what makes the
client-side replica viable: we can create our own AppContainer token for the
service-created profile and apply the policies with it.

## 4. The three BFS control codes — [evidence]

Dispatched by `BfsDeviceIoControl` (0x5c60) on `*(DWORD*)(in+24)` vs.:

| code | handler | in-buffer | meaning |
|---|---|---|---|
| `0x224608` | `BfsProcessQueryPolicySizeRequest` | 8 | size of the policy store (query) |
| `0x22460F` | `BfsProcessQueryPolicyRequest` | token | dump policy store |
| `0x228004` | `BfsProcessSetPolicyRequest` | 0x30 | set one path policy (below) |
| `0x228010` | `BfsProcessDeletePolicyEntryRequest` | 8 (token) | delete the whole `{userSid, appContainerSid}` policy entry |
| `0x228014` | `BfsProcessCreatePolicyEntryRequest` | 0x10 `{token, u32 flags}` | create the policy entry; only with `Feature_BfsInMemoryPolicies` enabled; `flags&1` = 1 → in-memory (no policy-store file writes) |

### `0x228004` (set one policy) — in-buffer, 0x30 bytes

```text
+0x00 HANDLE   sandbox        AppContainer token handle (see §2)
+0x08 DWORD    type           1 = file, 2 = directory (from GetFileAttributesExW)
+0x0C DWORD    kind           1 = read-write, 2 = read-only, 4 = deny, 6 = enumerate
+0x10 DWORD    flags          2, or 0 when kind==2 and PathIsRootW(path)
+0x14 UNICODE_STRING ntPath   RtlDosPathNameToNtPathName_U_WithStatus of the DOS path
+0x24 .. 0x2C  zero           (+0x28 dword: 0 = add/modify, 2 = delete — BfsDeleteEntry)
```

Handler behaviour: references the token, checks applicability, queries
`TokenUser` + `TokenAppContainerSid`, opens the path itself
(`ZwOpenFile(GENERIC_READ, FILE_OPEN, share 3)`, `FILE_NON_DIRECTORY_FILE`
for files / `FILE_DIRECTORY_FILE` for dirs; deny-kind opens with
`OBJ_CASE_INSENSITIVE` instead of `OBJ_KERNEL_HANDLE`, i.e. visible to bfs —
applying deny for a path the policy itself then blocks is prevented this way),
normalizes the name via `FltGetFileNameInformationUnsafe`, looks up / creates
the policy entry, and `BfsAddOrModifyEntry(volume, fileName, ...)`.

**Correction (found empirically, 2026-10-13):** the FIX-PLAN and an earlier
version of this file labelled kind 1 "read-only" — wrong. `SbepCreateSandbox`
passes the config vectors in fbs order (`fs_read_write` first) into
`ApplyFilesystemPolicy`, so cfg+32 → first loop → kind 1 is applied to the
**read-write** vector and kind 2 to the **read-only** vector. Verified by
enforcement: a kind-1 policy on a file allowed `GENERIC_WRITE`, a kind-2
policy denied it. The root-path flags exception belongs to read-only grants
(kind 2).

### `0x228014` (create policy entry / in-memory toggle)

`BfsProcessCreatePolicyEntryRequest`: hash(`TokenUserSid`) ⊕ hash(`AppContainerSid`)
→ `BfsLookupPolicyEntryHashTable`; if an entry exists it is removed first
(`BfsRemovePolicyEntry`), then `BfsInsertPolicyEntry(..., hash, userSid,
appContainerSid, flags&1 /*in-memory*/, ...)`. `flags&1 == 1` is what makes
`ApplyFilesystem` skip the file-backed policy-store writes (the 4.9.2 A cost
inside each `0x228004`).

## 5. Cleanup — the service does it for us

`SandboxFilesystem::RemoveFileSystemPolicy(SRWLock, appContainerToken)`
(0x379e8) sends `0x228010 {appContainerToken}` and then
`DetachIfUnused`. Callers: the `SandboxInstance` destructor path,
`SandboxRegistry::TeardownSandboxResources` (0x250f0), and one more site
(0x62418). So when the environment is closed service-side, the BFS policy
entry — ours included, since it is keyed by the same
`{userSid, appContainerSid}` — is removed. The client-side fast path needs **no
cleanup code of its own**; it must simply not close the environment before the
child exits.

One caveat: if we enable in-memory policies (0x228014) with our token and the
service later also runs with policies on the same `{userSid, appContainerSid}`
pair, both write into the same entry; two environments of the same profile
would collide (0xC0000035 from 0x228014). Not an issue when every environment
uses a fresh `Sandbox.{guid}` profile, which is what BazelSandbox.exe does.

## 6. Implications for the client-side fast path

1. **Create with empty fs vectors**: `SbepCreateSandbox` skips
   `ApplyFilesystemPolicy` entirely (the `if (any non-empty)` guard) — the
   1 ms/path cost disappears; the profile creation
   (`CreateAppContainerProfile`) and everything else stays identical.
2. **Get the AppContainer SID** of the created environment via
   `SbeGetSecurityEnvironmentAppContainerSid` (export 23) — no need to guess
   the `Sandbox.{guid}` name.
3. **Create our own AppContainer token** for that SID:
   `CreateAppContainerToken(userToken, appContainerSid, &token)` (kernelbase,
   private export — the very call the service makes). TokenUser must match:
   BazelSandbox.exe runs as the same user that owns the actions, and the
   service impersonates the RPC caller when creating the profile, so the user
   SIDs line up.
4. **Apply policies ourselves**: open `\\.\GLOBALROOT\Device\Bfs`
   (GENERIC_READ|GENERIC_WRITE, share 7), optional `0x228014 {token, 1}`
   (in-memory), then per path: `GetFileAttributesExW` → type; kind mapping
   ro=1 rw=2 deny=4 enumerate=6; flags 2 (0 for root read-only grants);
   `RtlDosPathNameToNtPathName_U_WithStatus`; `0x228004`, 0x30 bytes.
   Deny kind 4 with a missing path is deferred to a second pass that re-queries
   the attributes and forces type=2; any failure there throws.
   `ERROR_ACCESS_DENIED` for kind != 4: duplicate the token (SecurityImpersonation),
   `CheckFileAccessRights(dupToken, path)`; if it says "access allowed" the
   denial is real → throw, else skip the path silently.
5. **No attach work in the common case**: bfs auto-attaches to NTFS volumes
   (`C:` here). Non-NTFS volumes would still need `FilterAttachAtAltitude` —
   out of scope for the probe (Bazel's execroot is on the system drive).
6. **Spawn unchanged**: same `CreateProcessW` with attribute 35. The child runs
   with the service's AppContainer token; bfs matches our policies by SIDs (§3).
7. **Lifecycle**: keep the environment open while the child runs; closing it
   removes all BFS policies for the pair (§5), including ours.

## 7. SID discovery (client-side) — [verified live on psec2]

The spec has no container-name field; `SbeCreateProcessSecurityEnvironment`
passes a hard-coded `nullptr` name into `SbepCreateSandbox`, which then does
`CoCreateGuid()` and `CreateAppContainerProfile("Sandbox.{guid}", …)` while
impersonating the RPC caller. `SbeGetSecurityEnvironmentAppContainerSid`
resolves the handle against the *service-side* `SandboxRegistry`, so it is
useless from the client. The RPC returns only the registry handle.

What the client can see: while the environment is open, the profile shows up
as `%LOCALAPPDATA%\Packages\sandbox.{guid}` (deleted when the environment is
closed). Verified live:

```text
before: 5 sandbox.* dirs        open env: + sandbox.{63c3aa90-b345-4226-a7e0-67371b1764e2}
nttest derivesid sandbox.{63c3aa90-b345-4226-a7e0-67371b1764e2}
  → S-1-15-2-1849738845-768139239-406476515-64625325-723812385-3861382227-1630211993
child (nttest token, inside that env):
  AppContainerSid=S-1-15-2-1849738845-768139239-406476515-64625325-723812385-3861382227-1630211993   identical
```

(HKCU `…\AppContainer\Mappings` does **not** get an entry for these
service-created profiles — the Packages dir is the only client-visible trace.)

Recipe for the client-side fast path (as implemented in FastSandbox.cpp,
validated on psec2 and the VM):
1. snapshot the `Packages` `sandbox.*` dirs under the create mutex,
2. `CreateProcessSecurityEnvironment` (empty fs vectors),
3. diff → the new dir's moniker, `DeriveAppContainerSidFromAppContainerName`
   → AppContainerSid,
4. `CreateAppContainerToken(ownToken, {sid, &caps, 1}, &token)` — the second
   argument is a `{PSID sid; void* caps; DWORD count; DWORD pad;}` struct (it
   goes straight into `NtCreateLowBoxToken`), and `caps` must contain the
   **AgenticAppContainer** capability (resolved from its name via
   `DeriveCapabilitySidsFromName`): the service adds it to every environment
   token via `ApplyCapabilities`, and with `Feature_AgenticAppContainerBfs-Support`
   on, `bfs!BfsIsApplicableToken` rejects AppContainer tokens without it
   (0xC000A200). A bare `PSID` instead of the struct dereferences garbage
   (0xC0000005 inside kernelbase),
5. apply BFS policies client-side (§4; kind 1 = read-write, kind 2 =
   read-only — see the correction above),
6. spawn with attribute 35 as today.

Race: two concurrent creates produce two new dirs, and the diff cannot tell
which is ours. FastSandbox.cpp holds a named mutex (`Local\BazelPsecFast-FsCreate`)
across (snapshot → create → diff) — with empty vectors that window is
~40 ms; the BFS policy application itself runs outside the lock (the bfs
table is push-lock protected and takes concurrent writers). Without the
mutex, a concurrent run on the VM mis-assigned a SID and an action failed
with `trampoline: CreateProcessW failed: 5`; with the mutex, 3 consecutive
`--jobs=8` runs of the psectests suite passed 4/4.

## 8. Open questions

- `CreateAppContainerToken` is a *private* kernelbase export
  (`api-ms-win-security-base-private-l1-1-1`). It is the same call the service
  makes, so availability is guaranteed on this OS, but it could change.
- The AppContainer token we create has `CapabilityCount` from our call
  (the service token had 1 capability from the spec). BFS does not look at
  capabilities (except the agentic path), so this should not matter for
  enforcement.
- Impersonation: `ApplyFilesystem` impersonates the *user* token for
  `GetFileAttributesExW` and the access-denied retry. The client is the user,
  so its own token is equivalent; no impersonation dance needed client-side.
- `flags&1` of 0x228014: we pass 1 (in-memory). If that turns out to be
  rejected (feature off), fall back to file-backed policies (still removes
  phase 1, the 73 %).
