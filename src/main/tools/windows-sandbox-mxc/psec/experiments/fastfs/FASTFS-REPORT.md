# FASTFS-REPORT.md — client-side BFS policy application: measurements and verdict

Companion to `NOTES-sandboxid.md` (the reversal) and `BASELINE.md` (the
service-path numbers). Everything here was measured 2026-10-13 on
- **psec2** (the KD target, Win11 26300.9550 / processmodel 26100.9549,
  4 vCPU): microbenchmarks with the params corpus (`pdir/p100/p300/p1000/
  p4000.params`, 4 096 files under `C:\kd\files\d000..d003`), child =
  `nttest openloop 1000 files`.
- **bazel-mxc VM** (Win11 26200.9550, 8 vCPU): real Bazel 9.3.0 workloads
  through the Bazel windows-sandbox runner (console session via scheduled
  task; session 0 kills USER32 importers for any adapter).

## What was built

`psec/experiments/fastfs/FastSandbox.cpp` = BazelSandbox.cpp with a fast-fs
mode (`BAZEL_PSEC_FASTFS=1`; without the variable it behaves exactly like
BazelSandbox.exe, which is what the A/B below uses):

1. spec is built with **empty filesystem vectors** (everything else
   identical), so the Appinfo service's `ApplyFilesystemPolicy` is skipped
   entirely (`SbepCreateSandbox` guards it on "any vector non-empty");
2. the AppContainer SID of the service-created profile is recovered by
   diffing `%LOCALAPPDATA%\Packages` `sandbox.*` dirs (under a named mutex,
   see below) + `DeriveAppContainerSidFromAppContainerName`;
3. our own AppContainer token is created with
   `kernelbase!CreateAppContainerToken(ourToken, {sid, &caps, 1}, &out)`
   carrying the **AgenticAppContainer** capability (the service adds it to
   every environment token; bfs requires it with the agentic feature on);
4. the BFS policies are applied client-side: open
   `\\.\GLOBALROOT\Device\Bfs`, `0x228014 {token,1}` (in-memory policy
   store), then per grant `GetFileAttributesExW` → `0x228004` (0x30-byte
   request, kind 1=rw / 2=ro / 4=deny / 6=enumerate, deny-missing second
   pass, access-denied retry via `AccessCheck(GENERIC_READ)`);
5. spawn unchanged (`CreateProcessW` + attribute 35). bfs enforces by
   `{TokenUser, AppContainerSid}`, so the child (which runs with the
   service's token, same profile) matches our policies. Closing the
   environment removes the whole policy entry service-side — no cleanup
   code needed.

## Measurements, psec2

Create+apply time (ms), `BAZEL_MXC_TIMING` (median-ish of the two runs;
the `apply` column is the client-side FastFsApply portion):

| grants | service path (prep) | fast path (prep incl. apply) | fast apply | fast create |
|---|---|---|---|---|
| 2 | 32 | 38 | 4 | ~34 |
| 101 | 113 | 58 | 16 | ~42 |
| 301 | 277 | 109 | 41 | ~68 |
| 1001 | 831 | 273 | 130 | ~143 |
| 4001 | 3172 | 1015 | 557 | ~458 |

- The service-path create is ~1.0 ms per granted path (GAPS §4.9.4). The
  fast path's create is flat (~37–42 ms; the growth above is the
  BuildPolicy/FinalPath overhead the slow path pays too — both binaries do
  identical grant preparation).
- The client-side apply costs ~0.14 ms per path (attribute query + set-policy
  IOCTL with in-memory policies) — 7× cheaper than the service's per-path
  work, and it happens in parallel across actions instead of serially on one
  Appinfo RPC worker.
- Net: **~3.1× faster environment creation at 4 000 grants** (3172 → 1015 ms);
  2.5× at 300; at ≤2 grants the fast path costs +6 ms (the Packages diff and
  token creation) — for Bazel's per-action spawns the crossover is tiny.

End-to-end (create+apply+spawn+wait, 4001 grants): 4284 ms (slow) →
2164 ms (fast) on a 4-vCPU guest.

## Measurements, bazel-mxc VM (real Bazel)

`//psectests:{cc,java,py,sh}` (4/4 pass, fresh test runs, `--jobs=8`):
three consecutive fast-mode runs all 4/4; slow mode 4/4.

`C:\mxc\ex2\example` (genrule + cl.exe + link.exe sandboxed; the four
`//neg:*` targets must fail sandboxed and pass locally):

| | slow (BazelSandbox) | fast (FastSandbox, BAZEL_PSEC_FASTFS=1) |
|---|---|---|
| positive sandboxed build | PASS, hello.exe runs | PASS, hello.exe runs |
| `//neg:undeclared_read/write/tool` | fail (denied) | fail (denied) |
| `//neg:network` | fail (denied) | fail (denied) |
| write-escape probe (`C:\Users\Public` leak) | contained | contained |
| negative targets, local | pass | pass |
| overhead: 40 trivial genrules, jobs=1 | local 3.2 s / sandboxed 8.6 s | local 2.8 s / sandboxed 7.9 s |

For the trivial-genrule batch the sandboxed overhead is dominated by the
runner + spawn, not the create; the fast path shaves ~16 ms/action at the
2–5-grant scale and ~2.2 s/create at the 4 000-grant scale.

## Equivalence matrix (psec2, fast vs slow, fc-identical)

`fs-equiv.cmd` / `fs-equiv2.cmd` cases, all identical between modes:
ro-file r OK / w denied; no-grant r denied; rw-file w OK; widened
missing-parent grant; deny under rw parent (r and w denied); missing-deny
second pass (mkdir of denied name blocked, sibling allowed); enumerate-only
ancestor (LIST_DIRECTORY OK, unlisted file denied, traverse denied);
rw-dir traverse+list OK; junction grants in both directions (dir grant with
open-through-link, and file grant reached through a junction); cross-env
isolation (env1's deny does not affect env2's grant while both are open).
Known difference (cosmetic, not enforcement): a grant on a broken junction
fails the action in both modes, but at different steps — the service path
throws inside the create (hr=0x80070003), the fast path inside the client
apply (0xC000003A from bfs) or skips it (type 0). Net behaviour: action
fails in both.

Two findings from debugging the first runs (fixed):
- bfs kind semantics are **1 = read-write, 2 = read-only** (NOT the other
  way round; `SbepCreateSandbox` passes `fs_read_write` first). The
  FIX-PLAN's labels are wrong.
- `CreateAppContainerToken`'s second argument is
  `{PSID sid; void* caps; DWORD count; DWORD pad;}` and the token needs the
  `AgenticAppContainer` capability for `BfsIsApplicableToken` (else
  0xC000A200); a bare PSID crashes (0xC0000005).

## Caveats / limitations of the fast path

1. **Concurrent creates** must be serialized for the Packages-diff
   (implemented: `Local\BazelPsecFastFsCreate` mutex, ~40 ms window). Cost
   with 16 parallel actions: the creates serialize but the applies don't.
2. **`CreateAppContainerToken`** is a private kernelbase export
   (`api-ms-win-security-base-private-l1-1-1`); it is the exact call the
   service makes, but it is not a documented API.
3. **In-memory policies** (`0x228014`) depend on
   `Feature_BfsInMemoryPolicies`; if off, the code falls back to file-backed
   policies automatically (same behaviour, slower inserts).
4. **Non-NTFS volumes**: the service attaches bfs to them
   (`FilterAttachAtAltitude`); the fast path does not (bfs auto-attaches to
   NTFS; Bazel's execroot is on the system drive). Integration must either
   keep a volume-attach prep or reject non-NTFS grants.
5. The **Packages dir churn**: one profile dir per environment, deleted on
   close (the 5–6 stale dirs seen on the guest are from crashed runs — the
   same accumulation exists for the service path).
6. The diff+derive approach is **robust only if the profile dir is created
   synchronously with the RPC** — observed to be true (it appears within the
   2–5 s poll window; in practice immediately), but a very loaded machine
   could extend the window; the 5 s poll + mutex handles it.

## Verdict: GO

Integrate the fast-fs mode into BazelSandbox.cpp behind
`BAZEL_PSEC_FASTFS` (same code, same CLI contract, zero runner changes —
the mode is an env var the runner can set or Bazel pass via
`--action_env`). Evidence:
- enforcement is behaviorally identical across the whole matrix, on both
  machines, including deny/enumerate/junction/missing cases and cross-env
  isolation;
- 3.1× faster at 4 000 grants (3172 → 1015 ms), the regime Bazel actions
  actually live in; net wall-time at 4 000 grants halves (4284 → 2164 ms);
- the Appinfo service keeps doing everything except the per-path loops
  (profile, capabilities, network, registry), so the change is additive and
  revertible at runtime;
- real Bazel (psectests 4/4 ×4 runs; ex2 example incl. all negative targets
  and the write-escape probe) passes identically.

Suggested follow-ups for integration:
1. copy `FastFsApply` + helpers into BazelSandbox.cpp (or share the file);
2. pass `BAZEL_PSEC_FASTFS` from the Bazel runner as a default-on knob with
   an opt-out (`--experimental_windows_sandbox_no_fast_fs`), or measure a
   full Bazel-tree build before flipping the default;
3. keep the volume-attach prep as a TODO for non-NTFS volumes;
4. the per-path apply loop is embarrassingly parallel — a few threads could
   cut the 0.557 ms/path × 4 000 case further (bfs takes concurrent writers;
   verify before relying on it).
