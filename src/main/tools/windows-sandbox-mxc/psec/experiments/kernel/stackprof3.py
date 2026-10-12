#!/usr/bin/env python3
"""stackprof3.py <csv> <modules.txt> <bfs-funcs.txt> <proc>: pair StackWalk rows with the preceding SampleProf of the same
thread (profile stacks only), for process <proc>. Prints inclusive counts for bfs functions and writes the top unique frame
addresses (<csv>.frames) for symbolization."""
import sys, csv, collections
csvf, modf, funcf, proc = sys.argv[1:5]; proc = proc.lower()
mods = [(p[0], int(p[1],16), int(p[2],16)) for p in (l.split() for l in open(modf)) if len(p) >= 3]
funcs = [(int(s,16), int(e,16), n) for s, e, n in (l.split() for l in open(funcf))]
bfsbase, bfssize = next((b, sz) for n, b, sz in mods if n == 'bfs')
def bfsfn(ip):
    off = ip - bfsbase
    return next((n for s, e, n in funcs if s <= off < e), f'bfs+{off:x}')
pidname, tidpid = {}, {}; last = {}; nprof = 0; stacks = []
with open(csvf, encoding='utf-8', errors='replace') as f:
    rd = csv.reader(f); next(rd)
    for i, row in enumerate(rd):
        if len(row) < 20: continue
        ev, ty = row[0].strip(), row[1].strip(); ud = [c.strip().strip('"') for c in row[19:]]
        if ev == 'Process' and ty in ('DCStart', 'Start'):
            try: pid = int(ud[1], 0)
            except: continue
            name = next((c for c in ud if c.lower().endswith('.exe')), None)
            if name: pidname[pid] = name
        elif ev == 'Thread' and ty in ('DCStart', 'Start'):
            try: tidpid[int(ud[1], 0)] = int(ud[0], 0)
            except: pass
        elif ev == 'PerfInfo' and ty == 'SampleProf':
            try: last[int(ud[1], 0)] = ('prof', i)
            except: pass
        elif ev == 'StackWalk':
            try: pid = int(ud[1], 16); tid = int(ud[2], 0); frames = [int(c, 16) for c in ud[3:] if c.startswith('0x')]
            except: continue
            kind, at = last.get(tid, ('none', -1))
            if kind == 'prof' and i - at <= 6 and pidname.get(pid, '').lower() == proc:
                stacks.append(frames); nprof += 1
            last[tid] = ('other', i)
        else:
            # any other event on this thread breaks the pairing (CSwitch etc. are logged with the thread id in columns 10)
            pass
print(f"profile stacks for {proc}: {len(stacks)}")
incl = collections.Counter(); frames_c = collections.Counter()
for fr in stacks:
    seen = set()
    for a in fr:
        if a in seen: continue
        seen.add(a)
        if bfsbase <= a < bfsbase + bfssize: incl['bfs!' + bfsfn(a)] += 1
        elif a >= 0xFFFF800000000000: frames_c[a] += 1
tot = max(len(stacks), 1)
print("--- inclusive, bfs functions")
for n, c in incl.most_common(14): print(f"{c:7d} {100.0*c/tot:6.2f}%  {n}")
with open(csvf + '.frames', 'w') as o:
    for a, c in frames_c.most_common(160): o.write(f"{a:x} {c}\n")
print("top kernel frames written:", csvf + '.frames')
