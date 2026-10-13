# Draft issue: every process security environment leaks a logon session, and `bfs.sys` leaks paged pool per granted path

Not filed. Windows 11 25H2 26200.9550 (`processmodel.dll`, `bfs.sys`
10.0.26100.9549), seen on a 16-thread physical machine and reproduced on an
8-vCPU VM.

## Symptom

After enough environments since boot, `CreateProcessSecurityEnvironment`
fails with `0x800705AA` (`ERROR_NO_SYSTEM_RESOURCES`) when the spec has
filesystem paths, and `CreateProcessW` with
`PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT` fails with error 1450 for a new
environment without paths. Restarting the AppInfo service does not help;
only a reboot does. On the physical machine this happened after two clean
builds of Bazel with one environment per action (4 768 each) on top of the
earlier runs since boot.

## Leak 1: one logon session per environment

Pool tag `SeLs` grows by exactly one per environment created and closed, with
or without a process ever started in it, and whether the paths are applied by
the service or not (`churn` mode of `clientfs/clientfs_bench.cc`, 300 and
1 000 iterations: `SeLs +300`, `+1001`). The physical machine was at 65 582
outstanding `SeLs` allocations when creation started failing, the VM at
~1 600 in normal use. Restarting AppInfo leaves the count unchanged.

## Leak 2: `bfs.sys` keeps ~170 bytes per (environment, granted path)

Pool tags `BfsS` and `BfsG` (paged) grow by about three allocations per path
granted to an environment, and nothing frees them: not deleting the policy
entry (`0x228010`), not closing the environment, not the service's teardown.
Granting the same path to the same environment again allocates nothing; the
same path in a new environment allocates again (`bfsleak2` mode, 1 000 paths):

```
blank                        outstanding +2
apply A                      outstanding +3023
clear                        outstanding +3023
apply A again                outstanding +3023
clear                        outstanding +3023
apply B (disjoint)           outstanding +6023
close                        outstanding +6021
second env, apply A          outstanding +9044
close second                 outstanding +9042
```

The physical machine had 26.6 M `BfsS` and 13.3 M `BfsG` allocations
outstanding (1.46 GB + 0.83 GB). `fltmc unload bfs` / `fltmc load bfs`
reclaims it (and PSEC keeps working afterwards), but does not restore the
logon sessions of leak 1.

## Impact

A sandbox that creates one environment per build action (the natural design,
and what the Rust MXC adapter in this directory does) can create about 64 K
environments per boot. One clean
build of Bazel is 4 768 sandboxed actions and, with per-file grants, 2.3 M
granted paths (~400 MB of leaked paged pool).

## Workaround in Bazel's `windows-psec`

Create few environments and reuse them: with
`--experimental_windows_psec_client_fs` (default) environments are recycled
across policies (the filesystem policy is cleared and re-applied client side),
and the pool never closes one before the end of the command, so a build
creates about its peak concurrency + 32 + 8 environments.
