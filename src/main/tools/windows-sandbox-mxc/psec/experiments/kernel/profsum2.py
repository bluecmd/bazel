#!/usr/bin/env python3
"""profsum2.py <csv> <modules.txt> <bfs-funcs.txt> [proc ...]: CPU samples (PerfInfo/SampleProf, 1 kHz) per process and,
for the selected processes, by leaf module / bfs function; writes <csv>.topaddrs (nt/ntfs/fltmgr leaf addresses)."""
import sys, csv, re, collections
csvf, modf, funcf = sys.argv[1:4]; want = set(a.lower() for a in sys.argv[4:]) or {'nttest.exe'}
mods = [(p[0], int(p[1],16), int(p[2],16)) for p in (l.split() for l in open(modf)) if len(p) >= 3]
funcs = [(int(s,16), int(e,16), n) for s, e, n in (l.split() for l in open(funcf))]
bfsbase = next(b for n, b, sz in mods if n == 'bfs')
def mod_of(ip):
    for n, b, sz in mods:
        if b <= ip < b+sz: return n
    return 'user' if ip < 0xFFFF800000000000 else 'kernel?'
def bfsfn(ip):
    off = ip - bfsbase
    return next((n for s, e, n in funcs if s <= off < e), f'bfs+{off:x}')
pidname, tidpid, images = {}, {}, collections.defaultdict(list)
samples = []  # (tid, ip)
with open(csvf, encoding='utf-8', errors='replace') as f:
    rd = csv.reader(f); next(rd)
    for row in rd:
        if len(row) < 20: continue
        ev, ty = row[0].strip(), row[1].strip(); ud = [c.strip().strip('"') for c in row[19:]]
        if ev == 'Process' and ty in ('DCStart', 'Start'):
            try: pid = int(ud[1], 0)
            except: continue
            name = next((c for c in ud if c.lower().endswith('.exe')), None)
            if name: pidname[pid] = name
            if 'System' in ud: pidname.setdefault(pid, 'System')
        elif ev == 'Thread' and ty in ('DCStart', 'Start'):
            # user data: ProcessId, TThreadId, ...
            try: tidpid[int(ud[1], 0)] = int(ud[0], 0)
            except: pass
        elif ev == 'Image' and ty in ('DCStart', 'Load'):
            try: images[int(ud[2], 0)].append((int(ud[0],16), int(ud[1],16), next(c for c in reversed(ud) if '.' in c).split('\\')[-1]))
            except: pass
        elif ev == 'PerfInfo' and ty == 'SampleProf':
            try: samples.append((int(ud[1], 0), int(ud[0], 16)))
            except: pass
pidname.setdefault(4, 'System'); pidname.setdefault(0, 'Idle')
perproc = collections.Counter(pidname.get(tidpid.get(tid, -1), f'pid{tidpid.get(tid, -1)}') for tid, ip in samples)
print(f"CPU samples (1 ms each): total {len(samples)}; " + ", ".join(f"{n}={c}" for n, c in perproc.most_common(7)))
sel = [(tid, ip) for tid, ip in samples if pidname.get(tidpid.get(tid, -1), '').lower() in want]
print(f"selected {sorted(want)}: {len(sel)} samples")
bym, byfn, addrs = collections.Counter(), collections.Counter(), collections.Counter()
for tid, ip in sel:
    m = mod_of(ip)
    if m == 'user':
        pid = tidpid.get(tid, -1); m = 'user:' + next((fn for b, sz, fn in images.get(pid, []) if b <= ip < b+sz), '?')
    bym[m] += 1
    if m == 'bfs': byfn[bfsfn(ip)] += 1
    if m in ('nt', 'ntfs', 'fltmgr', 'bfs'): addrs[ip] += 1
for m, c in bym.most_common(12): print(f"{c:8d} {100.0*c/max(len(sel),1):6.2f}%  {m}")
if byfn:
    print("--- bfs leaf functions"); [print(f"{c:8d}  {n}") for n, c in byfn.most_common(12)]
with open(csvf + '.topaddrs', 'w') as o:
    for a, c in addrs.most_common(80): o.write(f"{a:x} {c}\n")
