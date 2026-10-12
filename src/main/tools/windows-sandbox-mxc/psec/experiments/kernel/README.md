# Kernel-side experiments (section 4.9 of GAPS-all-actions-sandboxed.md)

Target: a KDNET-attached VM made with the `windbg` skill's `kdt` from the
`vdi/win11-golden-9550` image (kernel 10.0.26100.9549, `bfs.sys` SHA-256
`5f86642c…`, identical to the experiment VM's). `bfs-funcs.txt` is the
driver's function table (RVA start, end, name) exported from IDA; `modules.txt`
the guest's kernel module map from `lm`.

| file | what |
|---|---|
| `g.sh`, `gput.sh`, `gget.sh`, `g-fwd.sh` | ssh into the guest through a kubectl port-forward (retrying) |
| `kd-wu.ps1`, `kd-wu2.ps1` | installing a cumulative update in the guest as SYSTEM (DISM failed with 0x80070306 on the .9168 golden; the .9550 golden made it unnecessary) |
| `kd-setup.cmd` | 4 096 test files and params files for 1/100/1000/4000-file and directory policies |
| `trav.sh` | the `FILE_TRAVERSE` probes under a breakpoint on `bfs!BfsQueryAccessOnly` (4.9.1) |
| `kd-bench.cmd`, `kd-prof.cmd`, `kd-run-all.cmd`, `kd-fileio.cmd` | timings, WPR CPU profiles and a FileIO trace of the open loop and of a 4 000-path environment creation |
| `profsum2.py`, `stackprof3.py`, `lnagg.py`, `inclagg.py`, `symtop.sh` | sample counting per process/module, stack pairing, symbolization through the debugger's `ln` |
| `../MXC-ISSUE-traverse.md` | draft issue report for microsoft/mxc |
| `psec.wprp`, `kd-trace.cmd` | WPR profile (CSwitch, ReadyThread, SystemCall, SampledProfile + stacks, FileIO) and the recording of one 300-path environment creation plus 300 × 3 sandboxed opens |
| `etw2perfetto.py` | converts the `.etl` to Perfetto JSON (`python -I etw2perfetto.py psec.etl out.json.gz --etl-parser <site-packages of etl-parser> --modules modules.txt --bfs-funcs bfs-funcs.txt --symbols symbols-ln.txt`); decodes CSwitch/syscall/sample/stack/FileIo MOF payloads itself |
| `psec-trace.perfetto.json.gz` | the converted trace (section 4.9.3); open at https://ui.perfetto.dev |
| `symbols-ln.txt` | kernel addresses of the trace's syscall entry points and sample frames, resolved with `ln` on the target |
| `tracecheck.py`, `timeline.py`, `brokerseq.py` | sanity checks and the numbers quoted in 4.9.3 (syscall pairing, CPU per 50 ms, the broker's per-path sequence) |
