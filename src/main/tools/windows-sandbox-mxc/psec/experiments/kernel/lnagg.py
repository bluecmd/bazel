#!/usr/bin/env python3
"""lnagg.py <topaddrs> <ln output> <total samples>: sum sample counts per symbol (without +offset)"""
import sys, re, collections
counts = {int(a,16): int(c) for a, c in (l.split() for l in open(sys.argv[1]) if l.strip())}
sym = {}
for l in open(sys.argv[2]):
    m = re.match(r'\s*([0-9a-f]{16})\s+(\S+)', l)
    if m: sym[int(m.group(1),16)] = re.sub(r'\+0x[0-9a-f]+$', '', m.group(2))
tot = int(sys.argv[3]); agg = collections.Counter(); covered = 0
for a, c in counts.items():
    agg[sym.get(a, f'?{a:x}')] += c; covered += c
print(f"top addresses cover {covered} of {tot} samples ({100.0*covered/tot:.1f}%)")
for s, c in agg.most_common(30): print(f"{c:7d} {100.0*c/tot:6.2f}%  {s}")
