#!/usr/bin/env python3
"""stackprof.py <tracerpt csv> <modules.txt> <bfs-funcs.txt> [procname ...]
Uses StackWalk events (one per sampled-profile interrupt) of the named processes (default: BazelSandbox.exe nttest.exe System).
Prints: samples per process; inclusive share per bfs function (deepest bfs frame); leaf module shares; top leaf addresses (for ln)."""
import sys, csv, re, collections
csvf, modf, funcf = sys.argv[1:4]
want = set(a.lower() for a in sys.argv[4:]) or {'bazelsandbox.exe', 'nttest.exe', 'system'}
mods = []
for l in open(modf):
    p = l.split()
    if len(p) >= 3: mods.append((p[0], int(p[1], 16), int(p[2], 16)))
funcs = [(int(s, 16), int(e, 16), n) for s, e, n in (l.split() for l in open(funcf))]
bfsbase = next(b for n, b, sz in mods if n == 'bfs')
def mod_of(ip):
    for n, b, sz in mods:
        if b <= ip < b + sz: return n, ip - b
    return ('user' if ip < 0xFFFF800000000000 else 'kernel?'), 0
def bfsfn(ip):
    off = ip - bfsbase
    for s, e, n in funcs:
        if s <= off < e: return n
    return f'bfs+{off:x}'
pidname = {}; pidcmd = {}; images = collections.defaultdict(list)
rows = []
with open(csvf, encoding='utf-8', errors='replace') as f:
    rd = csv.reader(f); next(rd)
    for row in rd:
        if len(row) < 20: continue
        ev, ty = row[0].strip(), row[1].strip()
        if ev == 'Process':
            # user data: UniqueProcessKey, ProcessId, ParentId, SessionId, ExitStatus, DirectoryTableBase, Flags, UserSID, ImageFileName, ...
            ud = [c.strip().strip('"') for c in row[19:]]
            name = next((c for c in ud if c.lower().endswith('.exe')), None)
            pid = None
            for c in ud[1:3]:
                try: pid = int(c, 0); break
                except ValueError: pass
            if name and pid is not None:
                pidname[pid] = name
                cmd = next((c for c in ud if '.exe ' in c.lower() or c.lower().endswith('.exe') and ' ' in c), '')
                if cmd: pidcmd[pid] = cmd
            if 'System' in ud and 4 not in pidname: pidname[4] = 'System'
        elif ev == 'Image' and ty in ('DCStart', 'Load'):
            # user data: ImageBase, ImageSize, ProcessId, ImageChecksum, TimeDateStamp, ..., FileName
            ud = [c.strip().strip('"') for c in row[19:]]
            try:
                base = int(ud[0], 16); size = int(ud[1], 16); ipid = int(ud[2], 0)
            except (ValueError, IndexError): continue
            fn = next((c for c in reversed(ud) if '\\' in c or '.dll' in c.lower() or '.exe' in c.lower()), '?')
            images[ipid].append((base, size, fn.split('\\')[-1]))
        elif ev == 'StackWalk':
            ud = [c.strip() for c in row[19:]]
            try:
                pid = int(ud[1], 16); frames = [int(c, 16) for c in ud[3:] if c.startswith('0x')]
            except (ValueError, IndexError): continue
            rows.append((pid, frames))
pidname.setdefault(4, 'System')
byproc = collections.Counter(pidname.get(pid, str(pid)) for pid, _ in rows)
print("cmdlines:", {pidname.get(k,k): v[:80] for k, v in pidcmd.items() if pidname.get(k,"").lower() in want}); print("stack samples per process:", ", ".join(f"{n}={c}" for n, c in byproc.most_common(8)))
sel = [(pid, fr) for pid, fr in rows if pidname.get(pid, '').lower() in want]
tot = len(sel); print(f"selected: {tot} stacks from {sorted(want)}")
incl = collections.Counter(); leafmod = collections.Counter(); leafaddr = collections.Counter(); kernel_only = 0; bfs_any = 0
for pid, fr in sel:
    if not fr: continue
    leaf = fr[0]; m, off = mod_of(leaf)
    if m == 'user':
        m = 'user:?'
        for b, sz, fn in images.get(pid, []):
            if b <= leaf < b + sz: m = 'user:' + fn; break
    leafmod[m] += 1
    if m != 'user': leafaddr[leaf] += 1
    bfsframes = [x for x in fr if mod_of(x)[0] == 'bfs']
    if bfsframes:
        bfs_any += 1
        incl[bfsfn(bfsframes[-1])] += 1   # outermost bfs frame = the bfs entry point
        incl['  (leaf in bfs) ' + bfsfn(leaf)] += (m == 'bfs')
print(f"stacks with a bfs frame: {bfs_any} ({100.0*bfs_any/max(tot,1):.1f}%)")
print("--- inclusive by outermost bfs function (and leaf-in-bfs functions)")
for n, c in incl.most_common(30): print(f"{c:7d} {100.0*c/max(tot,1):6.2f}%  {n}")
print("--- leaf module")
for n, c in leafmod.most_common(15): print(f"{c:7d} {100.0*c/max(tot,1):6.2f}%  {n}")
with open(csvf + '.leafaddrs', 'w') as o:
    for a, c in leafaddr.most_common(60): o.write(f"{a:x} {c}\n")
print("top leaf addresses written to", csvf + '.leafaddrs')
