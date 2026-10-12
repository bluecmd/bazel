#!/bin/bash
# trav.sh <access-hex> <options-hex> [path]: open <path> inside an environment (read-only grant) with NtOpenFile(access, options)
# while breaking on bfs!BfsQueryAccessOnly; prints rcx (1 file / 2 dir open), DesiredAccess, Create.Options and the verdict (al) of each call.
S=$(dirname "$0"); KDT=~/.claude/skills/windbg/kdt; B=fffff802240a0000; P=${3:-C:\\kd\\files}
$KDT cmd psec2 "break; bc *; bp $B+0xc5a8; g" 15000 >/dev/null 2>&1
(timeout 90 $S/g.sh "cd /d C:\kd & C:\kd\BazelSandbox.exe -W C:\kd -r C:\kd\nttest.exe -r C:\kd\files -w C:\kd\out -- C:\kd\nttest.exe ntopen $P $1 $2" > $S/trav-$1-$2.out 2>&1 &)
for call in 1 2; do
  out=$($KDT cmd psec2 '' 30000 2>&1)
  echo "$out" | grep -q 'BfsQueryAccessOnly' || { echo "call $call: no breakpoint hit"; break; }
  $KDT cmd psec2 'r rcx; r $t0=poi(@rdx+10); r $t1=poi(@$t0+18); r $t2=poi(@$t1+8); dd @$t2+18 L1; dd @$t0+20 L1; gu; r al; k 1' 30000 2>&1 | grep -E '^\s*rcx|^[0-9a-f]{16}  |al=|#0' | sed "s/^/  call $call: /"
  $KDT cmd psec2 'g' 5000 >/dev/null 2>&1
done
sleep 4; echo "  probe: $(tail -1 $S/trav-$1-$2.out)"
$KDT cmd psec2 'break; bc *; g' 10000 >/dev/null 2>&1
