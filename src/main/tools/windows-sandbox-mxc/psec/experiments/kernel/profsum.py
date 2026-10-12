#!/usr/bin/env python3
"""profsum.py <tracerpt csv> <modules file> [bfs-funcs.txt]
Aggregate SampledProfile events by module (and by bfs function when the module is bfs).
modules file: lines "name base size" (hex base/size) from the debugger's lm output."""
import sys, csv, re, collections
csvf, modf = sys.argv[1], sys.argv[2]
funcs = []
if len(sys.argv) > 3:
    for l in open(sys.argv[3]):
        s, e, n = l.split(); funcs.append((int(s, 16), int(e, 16), n))
mods = []
for l in open(modf):
    p = l.split()
    if len(p) >= 3:
        try: mods.append((p[0], int(p[1], 16), int(p[2], 16)))
        except ValueError: pass
def mod_of(ip):
    for n, b, sz in mods:
        if b <= ip < b + sz: return n, ip - b
    return 'other', 0
bymod = collections.Counter(); byfn = collections.Counter(); total = 0; ipcol = None
with open(csvf, encoding='utf-8', errors='replace') as f:
    rd = csv.reader(f)
    hdr = next(rd)
    for row in rd:
        if len(row) < 2 or row[0].strip() != 'PerfInfo' or 'SampledProfile' not in row[1]: continue
        # tracerpt puts the payload fields after the fixed columns; find the first 0x... field = InstructionPointer
        ips = [c for c in row if re.match(r'^\s*0x[0-9A-Fa-f]{8,16}\s*$', c)]
        if not ips: continue
        ip = int(ips[0], 16); total += 1
        m, off = mod_of(ip); bymod[m] += 1
        if m.startswith('bfs'):
            name = 'bfs+?'
            for s, e, n in funcs:
                if s <= off < e: name = n; break
            byfn[name] += 1
print(f"samples: {total}")
for m, c in bymod.most_common(25): print(f"{c:8d} {100.0*c/max(total,1):6.2f}%  {m}")
if byfn:
    print("--- bfs functions")
    for n, c in byfn.most_common(30): print(f"{c:8d}  {n}")
