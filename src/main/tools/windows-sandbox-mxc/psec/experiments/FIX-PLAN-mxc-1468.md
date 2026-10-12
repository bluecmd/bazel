# Fix plan for microsoft/mxc#1468: per-path `GetVolumePathNameW` in `processmodel.dll`

Audience: an agent with write access to the Windows source of
`processmodel.dll` (`onecore\base\appmodel\execmodel\processmodel\lib\engine\sandboxfilesystem.cpp`)
and, optionally, `bfs.sys` and `KernelBase.dll`. Everything below was derived
from the shipped binaries (10.0.26100.9549, public PDBs) and a kernel trace;
the source will differ in names of locals but not in structure. Line numbers
are the ones compiled into the `wil` throw sites and are therefore exact for
that build.

Background and measurements: `../../GAPS-all-actions-sandboxed.md` §4.9.2 –
§4.9.4 and the issue text in `MXC-ISSUE-volumepath.md`. In short: creating a
process security environment costs ~1 ms per granted path inside the AppInfo
service, 73 % of it in `SandboxFilesystem::EnsureBfsAttachedForPaths`, which
calls `GetVolumePathNameW` once per path, and that call probes every prefix
of the path three ways through the filter stack (58 system calls for a
five-component path). The remaining 20 % is `SandboxFilesystem::ApplyFilesystem`
(`GetFileAttributesExW` plus one set-policy IOCTL per path).

## 1. The code as it is today

All in `sandboxfilesystem.cpp`.

### Phase 1: `SandboxFilesystem::EnsureBfsAttachedForPaths` (RVA `0x36d30`)

```text
EnsureBfsAttachedForPaths(ro, rw, deny, enumerate, token, callerTag):
    containerId = BuildContainerId(appContainerSid, userSid)
    seenVolumes = unordered_set<wstring>          // local, lives for this call only
    forEach = [&](const vector<wstring>& paths) {     // lambda_3cd98340..., RVA 0x356c8
        for (path : paths) {
            if (PathIsUNCW(path)) continue;
            WCHAR vol[MAX_PATH];
            if (!GetVolumePathNameW(path, vol, MAX_PATH)) continue;   // <-- 0.73 ms per path
            if (PathIsUNCW(vol)) continue;
            key = MakeVolumeKey(vol);                                  // lowercase copy
            if (!seenVolumes.insert(key).second) continue;            // per-volume work below
            WCHAR fs[MAX_PATH];
            if (!GetVolumeInformationW(vol, ..., fs, MAX_PATH) || _wcsicmp(fs, L"NTFS") != 0)
                EnsureBfsAttachedToVolume(lock, containerId, vol, path, callerTag);
        }
    };
    forEach(ro); forEach(rw); forEach(deny);
    if (Feature_BfsEnumeratePolicy) forEach(enumerate);
```

`EnsureBfsAttachedToVolume` (RVA `0x36efc`, throw site line 571) takes the
object's SRW lock, checks `IsBfsFilterAttachedToVolume` (a
`FilterVolumeInstanceFindFirst/Next` loop looking for an instance named
`Bfs`) and if absent calls `AttachBfsToVolume` → `FilterAttachAtAltitude(L"Bfs",
vol, L"272000.5", ...)` (line 224), recording the created instance name in
two per-object maps (`volume → VolumeAttachment`, `containerId → set<volume>`).
This part is already per volume and is not the problem.

### Phase 2: `SandboxFilesystem::ApplyFilesystem` (RVA `0x35be8`)

```text
ApplyFilesystem(token, sandbox, flag, ro, rw, deny, enumerate):
    if all four vectors are empty: return
    hBfs = CreateFileW(L"\\\\.\\GLOBALROOT\\Device\\Bfs", GENERIC_READ|GENERIC_WRITE, ...)   // line 689
    if (Feature_BfsInMemoryPolicies && !flag)
        NtDeviceIoControlFile(hBfs, 0x228014, {sandbox, 1}, 0x10)                             // line 705
    ImpersonateLoggedOnUser(token)                                                            // line 252
    apply = [&](paths, deniedMissing, kind) {            // lambda_6fc995fd..., RVA 0x358b8
        for (path : paths) {
            type = CheckIfFileOrDirectory(path)          // GetFileAttributesExW; 1 file, 2 dir, 0 missing
            if (type == 0) { if (kind == 4 && deniedMissing) deniedMissing->push_back(path); continue; }
            flags = (kind == 1 && PathIsRootW(path)) ? 0 : 2
            RtlDosPathNameToNtPathName_U_WithStatus(path, &nt)
            NtDeviceIoControlFile(hBfs, 0x228004, {sandbox, type, kind, flags, nt, 0}, 0x30) // line 806 on error
            // ERROR_ACCESS_DENIED for kind != 4: DuplicateToken + CheckFileAccessRights, then throw or skip
        }
    };
    apply(ro, null, 1); apply(rw, null, 2);
    if (Feature_BfsEnumeratePolicy) apply(enumerate, null, 6);
    if (Feature_BfsPolicyDeny)      apply(deny, &missing, 4);
    RevertToSelf()
    if (Feature_BfsPolicyDeny && !missing.empty()) applyMissingDeny(missing)   // lambda_1576d3a8..., kind 4, type forced to 2
```

Both phases run on the one RPC worker thread that serves
`RAiCreateProcessSecurityEnvironment`; nothing is parallel and nothing is
cached between the paths of one call.

## 2. Why `GetVolumePathNameW` is the wrong tool here

Phase 1 only needs, per path, the volume the path lives on, in order to
decide once per volume whether `bfs` must be attached (only for non-NTFS
volumes, since `bfs` auto-attaches to NTFS). `KernelBase!GetVolumePathNameInternalW`
answers that by walking the path's prefixes from the leaf upward and, for
every prefix, running `GetDriveTypeW` (two `NtOpenFile`, one
`NtQueryVolumeInformationFile`), `BasepGetVolumeNameFromReparsePoint`
(`NtCreateFile` with `FILE_FLAG_OPEN_REPARSE_POINT` plus
`FSCTL_GET_REPARSE_POINT`) and `GetVolumeNameForRoot` (`NtOpenFile` plus
`IOCTL_MOUNTDEV_QUERY_DEVICE_NAME`), until a prefix turns out to be a
volume root. Every prefix costs ~130 µs through
`wdfilter`/`luafv`/`fileinfo`/`bfs`/`ntfs`, and the cost is paid again for
the next path even when it shares all but the last component.

Invariant that makes caching correct: the volume of `D\x` equals the volume
of `D` unless `x` itself is a volume mount point (a directory reparse point
with `IO_REPARSE_TAG_MOUNT_POINT` whose target is `\??\Volume{...}\`). Files
are never mount points, and directory symlinks/junctions are not treated as
volume boundaries by `GetVolumePathNameW` either (it only recognises the
mount-point tag with a volume target), so the only leaf that can change the
answer is a directory with `FILE_ATTRIBUTE_REPARSE_POINT` set.

## 3. The change (processmodel.dll only)

Replace the per-path `GetVolumePathNameW` in the phase-1 lambda with a
per-call resolver that is memoised per directory and falls back to the
original API whenever it cannot prove the answer. Keep everything after the
volume name (key, `seenVolumes`, NTFS check, attach) unchanged.

### 3.1 Resolver

```text
struct VolumeResolver {
    // key: lowercase, normalised, no trailing separator except for roots; value: volume path name as GetVolumePathNameW returns it
    unordered_map<wstring, wstring> dirVolume;

    bool Resolve(const wstring& path, wstring& vol);
};

bool VolumeResolver::Resolve(path, vol):
    full = GetFullPathNameW(path)                 // pure string work, same CWD semantics as GetVolumePathNameW
    if (full is a root such as "C:\" or "\\?\Volume{...}\"):   return Slow(path, vol)
    parent = full without its last component
    key    = lower(parent)
    it = dirVolume.find(key)
    if (it == end):
        // Walk upward until a known directory or the root, then fill downward.
        if (!Resolve(parent, parentVol)) return Slow(path, vol);     // recursion bottoms out at Slow() on the root
        dirVolume[key] = parentVol                                   // Resolve(parent) already inserted it, this is a no-op
    parentVol = dirVolume[key]
    // The leaf can only change the volume if it is a directory reparse point.
    WIN32_FILE_ATTRIBUTE_DATA a;
    if (!GetFileAttributesExW(full, GetFileExInfoStandard, &a))       // missing leaf: cannot be a mount point
        { vol = parentVol; return true; }
    if ((a.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
        return Slow(path, vol);                                      // exact answer for the rare case
    vol = parentVol
    if (a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) dirVolume[lower(full)] = vol
    return true

bool VolumeResolver::Slow(path, vol):
    WCHAR buf[MAX_PATH];
    if (!GetVolumePathNameW(path, buf, MAX_PATH)) return false;      // identical to today, including the silent skip
    vol = buf
    if (path names a directory) dirVolume[lower(full)] = vol
    return true
```

Cost per path after the change: one `NtQueryFullAttributesFile` (≈ 50 µs
on the traced VM) instead of 58 system calls (≈ 730 µs). Per distinct
directory that is not yet memoised: the same attribute query once, plus one
real `GetVolumePathNameW` per volume root. For a build sandbox (thousands of
files under a few hundred directories, all on one volume) the phase-1 cost
drops from ~0.73 ms/path to ~0.05 ms/path, and §3.3 removes that too.

### 3.2 Wiring

In `EnsureBfsAttachedForPaths` create one `VolumeResolver` next to the
existing `seenVolumes` set so it spans all four vectors, and in the lambda
replace

```cpp
if (GetVolumePathNameW(path.c_str(), vol, ARRAYSIZE(vol)) && !PathIsUNCW(vol))
```

with

```cpp
std::wstring vol;
if (resolver.Resolve(path, vol) && !PathIsUNCW(vol.c_str()))
```

Keep the `PathIsUNCW(path)` early-out before it; UNC paths never reach the
resolver, as today.

### 3.3 Fold the attribute query into phase 2 (second step, optional)

Phase 2 already calls `GetFileAttributesExW` on every path
(`CheckIfFileOrDirectory`). Once §3.1 is in, the only remaining per-path
system call in phase 1 is that same query. Either:

- have phase 1 record `path → (type, attributes)` in a map that phase 2's
  `CheckIfFileOrDirectory` consults first (both phases run on the same thread
  within one `ApplyFilesystemPolicy`; the map is a local of that function
  passed to both), or
- merge the two loops: per path, query attributes once, resolve the volume,
  attach if the volume is new, then issue the IOCTL. This changes ordering
  (attach interleaved with policy inserts instead of all attaches first);
  the attach is a `FilterAttachAtAltitude` and the inserts go into
  `bfs`'s policy store, so there is no dependency, but it is a larger diff
  and §3.1 alone already gives the bulk of the win.

Prefer the first variant.

### 3.4 What not to change

- `MakeVolumeKey`, `seenVolumes`, the NTFS check and
  `EnsureBfsAttachedToVolume` stay as they are; they are already per volume.
- The silent skips stay: a path for which `GetVolumePathNameW` fails today
  is skipped today (and `ApplyFilesystem` still tries to insert a policy for
  it). The resolver returns `false` in exactly the same cases because its
  only failure path is the original call.
- Do not try to be clever about `\\?\` prefixes, SUBST drives,
  `\\?\Volume{GUID}\` paths or 8.3 names: the memo is keyed on the
  normalised string, so two spellings of the same directory simply produce
  two correct entries, and the root of each spelling is resolved by the
  original API.

## 4. Correctness tests

Add a test (processmodel's existing TAEF suite for `SandboxFilesystem`, or a
new one) that builds a directory corpus and asserts, for every path in it,
`VolumeResolver::Resolve(p) == GetVolumePathNameW(p)` and that the set of
volumes handed to `EnsureBfsAttachedToVolume` is identical before and after
the change. The corpus must contain:

1. Plain NTFS files several levels deep under one directory, thousands of
   them (the common case; also the performance case).
2. A non-NTFS volume (exFAT or ReFS VHD) mounted as a drive letter, with
   grants on it. Expect exactly one attach.
3. The same volume mounted into a folder on `C:` with `mountvol`, with
   grants that name only files below the mount point and never the mount
   point itself. Expect one attach for the mounted volume, none for `C:`.
   This exercises the upward walk hitting a directory reparse point in the
   middle of the path, which must go through `Slow()`.
4. A grant on the mount-point directory itself (leaf is a directory
   reparse point → `Slow()`).
5. A junction and a directory symlink to a directory on another volume,
   with grants through them. The expected value is whatever
   `GetVolumePathNameW` returns today (it does not follow them); the
   resolver reaches the same answer because a junction is a directory
   reparse point and goes to `Slow()`.
6. Missing leaf files and missing intermediate directories in the
   read-only and in the deny vector (deny lists routinely name paths that
   do not exist yet). `GetVolumePathNameW` resolves those by walking up to
   the first existing prefix; the resolver inherits the parent's volume,
   which is the same volume.
7. Root grants (`C:\`, `\\?\C:\`), trailing backslashes, mixed case,
   forward slashes, relative paths (resolved against the service's CWD by
   both implementations), paths longer than `MAX_PATH` with the `\\?\`
   prefix, and a UNC path (skipped before the resolver, as today).
8. The same directory given once by long name and once by 8.3 name.
9. A file whose parent directory is itself a file (invalid path):
   `GetFileAttributesExW` fails, the parent lookup fails, the chain ends in
   `Slow()` on the root, which fails the same way as today.

Run the suite with `Feature_BfsEnumeratePolicy` and `Feature_BfsPolicyDeny`
both on and off; the resolver is shared across all four vectors.

## 5. Performance verification

Reproduce the issue's numbers before and after on the same machine. The
tooling in this directory does it end to end on a Windows 11 25H2 VM:

| step | tool |
|---|---|
| create the corpus (`C:\kd\files\d000..d003\f00000.txt …`) | `nttest.exe mkfiles` (`nttest.cpp`, built with `build-nttest.cmd`) |
| create an environment with N file grants and time it | `BazelSandbox.exe … @p1000.params`, `@p4000.params` with `BAZEL_MXC_TIMING` set; `kernel/kd-bench.cmd` runs none / 1 dir / 1 000 / 4 000 |
| kernel trace of the creation (CSwitch, SystemCall, FileIO, sampled stacks) | `kernel/psec.wprp`, `kernel/kd-trace.cmd` |
| per-phase and per-syscall attribution, Perfetto trace | `kernel/etw2perfetto.py` (needs the `etl-parser` package and the symbol files in `kernel/`), `kernel/brokerseq.py`, `kernel/brokerusr.py` |

Any PSEC client works instead of `BazelSandbox.exe`; what matters is N
file grants under the same few directories and the wall time of
`CreateProcessSecurityEnvironment`.

Targets, 2-vCPU VM, file-backed policy store (today's default):

| grants | today | after §3.1 | after §3.1 + §3.3 |
|---|---|---|---|
| 300 files | 391 ms | ≤ 120 ms | ≤ 100 ms |
| 1 000 files | 1 091 ms | ≤ 300 ms | ≤ 250 ms |
| 4 000 files | 3 807 ms | ≤ 1 100 ms | ≤ 900 ms |

What remains after that is phase 2: ~54 µs for the attribute query and
~130 µs for the set-policy IOCTL per path, the latter dominated by the
`ZwWriteFile`s of the file-backed policy store (§4.9.2 of the gap document).
In the trace, confirm that the broker thread's `NtOpenFile`, `NtFsControlFile`
and `NtDeviceIoControlFile(0x4D0008)` counts have collapsed from ~13, ~6 and
~7 per path to near zero, and that `NtQueryFullAttributesFile` is at 1 – 2
per path.

## 6. Follow-ups outside §3 (optional, in priority order)

1. **Turn on `BfsInMemoryPolicies` for this caller** (`processmodel.dll`,
   no code: the branch already exists at line 705 and issues IOCTL
   `0x228014` with `{sandbox, 1}` when the feature is enabled and the
   `bool` argument of `ApplyFilesystemPolicy` is false). Find out what that
   `bool` means (it is the fourth parameter of `ApplyFilesystemPolicy` and
   of `ApplyFilesystem`; likely "persist/registered" vs. ad-hoc PSEC
   environment) and whether the velocity feature can be enabled for PSEC
   environments. This removes the policy-store writes from the IOCTL, which
   are most of its 130 µs.
2. **Batch the set-policy IOCTL** (`processmodel.dll` + `bfs.sys`): a new
   IOCTL taking an array of `{type, kind, flags, UNICODE_STRING}` records so
   phase 2 makes one kernel transition per vector instead of per path. Only
   worth it after (1); with in-memory policies the per-IOCTL cost is the
   transition plus the insert, ~10 – 20 µs.
3. **`KernelBase!GetVolumePathNameInternalW`**: before running the three
   probes on a prefix, one `NtQueryAttributesFile` would tell it whether
   the prefix is a reparse point at all and skip
   `BasepGetVolumeNameFromReparsePoint` and `GetVolumeNameForRoot` for the
   common non-reparse prefix. That helps every caller of the API but is a
   public-API behaviour change that needs its own review; it is not needed
   for #1468 once §3 is in.
4. **Parallelism** is not needed: with §3 the per-path work is one cheap
   system call, and the RPC worker thread running a plain loop is fine.

## 7. Checklist for the implementing agent

- [ ] Read `sandboxfilesystem.cpp` around the `EnsureBfsAttachedForPaths` lambda and confirm the structure in §1 (names may differ).
- [ ] Add `VolumeResolver` (§3.1) as a file-local class or a private nested type of `SandboxFilesystem`; one instance per `EnsureBfsAttachedForPaths` call.
- [ ] Replace the `GetVolumePathNameW` call in the lambda (§3.2). Nothing else in the lambda changes.
- [ ] Add the equivalence test (§4) and run it with the feature flags in both states.
- [ ] Measure (§5) and paste the before/after table and the per-syscall counts into the PR.
- [ ] Optionally do §3.3 (first variant) in a second commit, re-measure.
- [ ] Note the `BfsInMemoryPolicies` question (§6.1) for the owners of the feature flag.

## 8. Access to the test VM (`psec2`)

The measurements in §5 were taken on the KDNET target `psec2`, a Windows 11
25H2 (26100.9549) VM on the `windbg` KubeVirt namespace of this machine's
cluster, kernel-debugger attached. It runs until its 48 h TTL from
2026-10-12 14:26 UTC unless reprieved
(`kubectl -n windbg annotate vm psec2 windbg.mainframe.dev/ttl=never --overwrite`).

| what | how |
|---|---|
| guest admin account | user `debug`; the password is printed by `~/windbg-mcp/skill/windbg/kdt credentials psec2` (it reads the cluster secret `kdt-sysprep`). Do not copy it into files or commits. |
| shell in the guest | `kernel/g-fwd.sh` keeps a port-forward of the guest's ssh on `127.0.0.1:2222` (already running in this session); then `kernel/g.sh "<cmd>"`, `kernel/gput.sh <local> C:/kd/<name>`, `kernel/gget.sh C:/kd/<name> <local>`. RDP/WinRM are on the same pod (3389, 5985) if a port-forward is added. |
| kernel debugger | ntoseye (WinDbg syntax) over MCP at `http://127.0.0.1:18501/mcp`, server name `windbg-psec2` (`kdt mcp psec2` prints the config, `~/.cache/kdt/psec2.mcp.json`). One-off: `kdt cmd psec2 'break; k; g' 20000`. Always leave the target running (`g`); a halted guest is frozen for everyone. |
| guest layout | `C:\kd\`: `BazelSandbox.exe`, `nttest.exe`, `files\d000..d003\` (4 096 test files), `pdir.params`, `p100.params`, `p1000.params`, `p4000.params`, `kd-*.cmd`, `psec.wprp`, WPR output `psec.etl`. |
| rebuilt binaries | copy a private `processmodel.dll` into the guest with `gput.sh` and swap it in with `g.sh` (TrustedInstaller ownership: `takeown`/`icacls` first, or use a test-signing boot and `bcdedit /set testsigning on`, then reboot; the debugger reattaches on its own). |
