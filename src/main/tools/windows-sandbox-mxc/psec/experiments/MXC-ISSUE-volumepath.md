# Draft issue for github.com/microsoft/mxc

**Title:** Process container: environment creation costs ~1 ms per granted path in `GetVolumePathNameW`

## Summary

`CreateProcessSecurityEnvironment` (PSEC contract 1.1, Windows 11 25H2
26200.9550, `processmodel.dll` 10.0.26100.9549) takes about 1 ms per path in
the policy, paid in the AppInfo service, and the time is not the policy
insert. Three quarters of it is `GetVolumePathNameW`, which
`SandboxFilesystem::EnsureBfsAttachedForPaths` calls once per granted path
to learn the path's volume. That call probes every prefix of the path three
times through the filter stack, so the cost is also linear in path depth.
With a few thousand file grants, which is what a build sandbox needs to
express "these inputs, read-only", environment creation takes seconds:

| grants | `CreateProcessSecurityEnvironment` |
|---|---|
| 1 directory | 40 ms |
| 300 files, 5 components deep | 391 ms |
| 1 000 files | 1 091 ms |
| 4 000 files | 3 807 ms |

(2-vCPU VM; the caller is idle in `NtWaitForSingleObject` throughout, one
RPC worker thread in `svchost -k netsvcs -s Appinfo` is at 100 %.)

## Where the time goes

Kernel trace (context switches, system calls, FileIO, sampled stacks) of a
300-file creation, user frames resolved with the public symbols of
`appinfo.dll`, `processmodel.dll` and `KernelBase.dll`:

| phase | function | share | per path |
|---|---|---|---|
| 1 | `SandboxFilesystem::EnsureBfsAttachedForPaths` | 73 % | `GetVolumePathNameW(path)`, `MakeVolumeKey`; `GetVolumeInformationW` / `EnsureBfsAttachedToVolume` only for a volume not seen before |
| 2 | `SandboxFilesystem::ApplyFilesystem` | 20 % | `GetFileAttributesExW` (54 µs) and the set-policy IOCTL `0x228004` (130 µs, includes the policy-store writes) |

The per-volume set in phase 1 caches the NTFS check and the attach, but
`GetVolumePathNameW` runs for every path. `KernelBase!GetVolumePathNameInternalW`
loops over the path's prefixes from the full path upward and on each one
calls `GetDriveTypeW` (two `NtOpenFile`, `NtQueryVolumeInformationFile`),
`BasepGetVolumeNameFromReparsePoint` (`CreateFile` with
`FILE_FLAG_OPEN_REPARSE_POINT`, `FSCTL_GET_REPARSE_POINT` → `STATUS_NOT_A_REPARSE_POINT`)
and `GetVolumeNameForRoot` (`NtOpenFile`, `IOCTL_MOUNTDEV_QUERY_DEVICE_NAME`
→ `STATUS_INVALID_PARAMETER` below the root). For
`C:\kd\files\d000\f00131.txt` that is 13 `NtOpenFile`, 8 `NtCreateFile`,
6 `NtFsControlFile`, 7 `NtDeviceIoControlFile` and 17 `NtClose` (11 µs each
through `wdfilter`/`luafv`/`fileinfo`/`bfs`/`ntfs`): 0.73 ms of the 0.93 ms
per path. All 300 grants share the same three ancestor directories and
nothing is remembered between them; a typical build-tree path has 10 – 14
components.

Totals for the broker thread over the 300 paths:

| system call | count | per path | total |
|---|---|---|---|
| `NtClose` | 5 191 | 17.3 | 64 ms |
| `NtOpenFile` | 3 951 | 13.2 | 66 ms |
| `NtCreateFile` | 2 438 | 8.1 | 40 ms |
| `NtDeviceIoControlFile` | 2 429 | 8.1 | 57 ms (the two `bfs` IOCTLs ≈ 10 ms of it) |
| `NtFsControlFile` | 1 824 | 6.1 | 13 ms |

## Expected

The volume of a path is the volume of its parent directory unless a mount
point sits in between, so one lookup per distinct parent directory (a
string-prefix cache in `EnsureBfsAttachedForPaths`), or one
`NtQueryVolumeInformationFile(FileFsVolumeInformation)` on the handle that
phase 2 opens anyway for `GetFileAttributesExW`, would give the same
answer for ~1 % of the cost. Either change is in `processmodel.dll` only.
Enabling `BfsInMemoryPolicies` (already supported by `ApplyFilesystem`
through IOCTL `0x228014`) would additionally remove the policy-store
writes from phase 2.

## Why it matters

A build sandbox (Bazel's `windows-sandbox` on PSEC) creates one environment
per action with the action's inputs as read-only grants, typically hundreds
to thousands of deep paths. At 1 ms per path the environment costs more
than many of the actions it protects, and the only workaround is to grant
whole directories, which widens what every action can read.

## Repro

Any `CreateProcessSecurityEnvironment` with N file grants under the same
directory; creation time grows linearly with N and with the depth of the
paths. A WPR trace with the SystemCall and FileIO keywords on the AppInfo
service shows the pattern above for each grant.
