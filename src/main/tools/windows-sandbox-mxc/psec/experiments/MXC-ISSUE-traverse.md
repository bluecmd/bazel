# Draft issue for github.com/microsoft/mxc

**Title:** Process container: `FILE_TRAVERSE` opens of a directory are denied under a read-only path grant (`bfs.sys` `BfsQueryAccessOnly` directory mask lacks bit 0x20), so `SetCurrentDirectory` into any read-only or enumerate-only path fails

## Summary

Inside a `processcontainer` (process security environment, PSEC contract 1.1,
Windows 11 25H2 26200.9550 / `bfs.sys` 10.0.26100.9549), a directory that is
granted **read-only** can be listed and stat'ed but cannot be opened with
`FILE_TRAVERSE` when the open carries `FILE_DIRECTORY_FILE`. That is exactly
the open `SetCurrentDirectoryW` performs, so `cd` into a read-only directory
fails with `ERROR_ACCESS_DENIED` (and `chdir` of every runtime that wraps it:
cmd.exe, PowerShell's start location, busybox, Bazel's test wrapper). The same
right is **allowed** when the open does not carry `FILE_DIRECTORY_FILE`, and
`FILE_LIST_DIRECTORY` with `FILE_DIRECTORY_FILE` is allowed, so this is not an
intended restriction but an asymmetric access mask. Enumerate-only paths
(`enumeratePaths`) deny `FILE_TRAVERSE` in every form.

## Repro

Any read-only grant, any directory under it, then from inside the container:

```
NtOpenFile(dir, FILE_TRAVERSE,              FILE_DIRECTORY_FILE)                -> STATUS_ACCESS_DENIED
NtOpenFile(dir, FILE_TRAVERSE | SYNCHRONIZE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) -> STATUS_ACCESS_DENIED  (= SetCurrentDirectoryW)
NtOpenFile(dir, FILE_TRAVERSE,              0)                                  -> STATUS_SUCCESS
NtOpenFile(dir, FILE_LIST_DIRECTORY,        FILE_DIRECTORY_FILE)                -> STATUS_SUCCESS
NtOpenFile(dir, FILE_READ_ATTRIBUTES,       FILE_DIRECTORY_FILE)                -> STATUS_SUCCESS
cmd.exe /c "cd /d <read-only dir>"                                              -> "Access is denied."
```

With a read-write grant all of them succeed. (A minimal probe: `nttest.exe
ntopen <path> <access-hex> <options-hex>` from
`src/main/tools/windows-sandbox-mxc/psec/experiments/nttest.cpp` on the
`windows-sandbox-psec-exe` branch of github.com/bluecmd/bazel, run through
`wxc-exec` or any `CreateProcessSecurityEnvironment` launcher.)

## Where it is

`bfs!BfsQueryAccessOnly(int kind, PFLT_CALLBACK_DATA)` decides whether an open
under a read-only grant is query-only. `kind` is 2 for opens with
`FILE_DIRECTORY_FILE`, else 1. It tests `OriginalDesiredAccess` against:

```
cmp   esi, 2
jnz   file
test  ebx, 0FFE1FF7Eh          ; directory open: allowed 0x001E0081 (LIST, READ_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE)
jmp   done
file:
call  Feature_BfsQueryOnlyAllowExecute…
test  ebx, 0FFE1FF56h          ; file open, feature on: allowed 0x001E00A9 (+ READ_DATA, READ_EA, EXECUTE)
test  ebx, 0FFE1FF76h          ; file open, feature off
setz  al
```

`FILE_EXECUTE` and `FILE_TRAVERSE` share bit 0x20. The
`BfsQueryOnlyAllowExecute` feature added it to the file mask only. Verified
with a kernel debugger: breakpoint on the function, our probe's directory open
arrives with `rcx = 2`, `OriginalDesiredAccess = 0x20`, `Create.Options =
0x01000001`, the function returns 0 and the caller
(`BfsCheckAndApplyPolicy+0xa0d`, from `BfsPreCreateOperation`) completes the
create with `STATUS_ACCESS_DENIED`. The enumerate-only path uses a second
constant (`0xFFEDFF76`) with the same omission.

## Expected

Traverse grants nothing a listing does not (the contained token even holds
`SeChangeNotifyPrivilege`, which bypasses traverse checks elsewhere), so the
directory mask should allow 0x20: `0xFFE1FF5E` instead of `0xFFE1FF7E`, and
likewise for enumerate-only paths. Until then any tool that changes directory
into a read-only input tree inside a container fails.

## Why it matters

Build sandboxes (Bazel's `windows-sandbox` on PSEC) grant inputs read-only and
run tools with the execroot or the runfiles tree as the working directory.
Every test wrapper `chdir`s into its runfiles directory; the only workaround
is to grant such directories read-write, which weakens the sandbox for no
security gain.
