#!/bin/bash
# symtop.sh <csv> <N>: the N most frequent sample addresses outside bfs, symbolized with the kernel debugger (ln)
S=$(dirname "$0"); KDT=~/.claude/skills/windbg/kdt
python3 - "$1" "$2" <<'PY' > $S/top-addrs.txt
import sys,csv,re,collections
c=collections.Counter(); tot=0
with open(sys.argv[1],encoding='utf-8',errors='replace') as f:
    rd=csv.reader(f); next(rd)
    for row in rd:
        if len(row)<2 or row[0].strip()!='PerfInfo' or 'SampledProfile' not in row[1]: continue
        ips=[x for x in row if re.match(r'^\s*0x[0-9A-Fa-f]{8,16}\s*$',x)]
        if not ips: continue
        tot+=1; c[int(ips[0],16)]+=1
print(tot)
for a,n in c.most_common(int(sys.argv[2])): print(f"{a:x} {n}")
PY
total=$(head -1 $S/top-addrs.txt)
cmds=$(tail -n +2 $S/top-addrs.txt | awk '{printf "ln %s; ", $1}')
$KDT cmd psec2 "break; $cmds g" 120000 2>&1 | grep -v dbgprint > $S/ln.out
python3 - "$S/top-addrs.txt" "$S/ln.out" "$total" <<'PY'
import sys,re
addrs=[l.split() for l in open(sys.argv[1]).read().split('\n')[1:] if l.strip()]
txt=open(sys.argv[2]).read()
# ntoseye ln output: lines like "(fffff802...)   nt!KiPageFault+0x...   |  (...)" ; map by order of appearance
names=re.findall(r'\(([0-9a-f]{16})\)\s+(\S+)', txt)
m={a:n for a,n in names}
tot=int(sys.argv[3]); agg={}
for a,n in addrs:
    sym=m.get(a.rjust(16,'0'),'?'); sym=re.sub(r'\+0x[0-9a-f]+$','',sym); agg[sym]=agg.get(sym,0)+int(n)
for sym,n in sorted(agg.items(), key=lambda x:-x[1])[:40]: print(f"{n:7d} {100.0*n/tot:6.2f}%  {sym}")
PY
