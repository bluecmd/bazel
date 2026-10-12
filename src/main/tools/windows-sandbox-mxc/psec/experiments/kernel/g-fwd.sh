#!/bin/bash
# g-fwd.sh: keep a port-forward to the psec target's ssh on 127.0.0.1:2222, restarting it when it drops
while true; do
  POD=$(kubectl -n windbg get pod -l windbg.mainframe.dev/target=${TARGET:-psec2} -o name 2>/dev/null | head -1)
  [ -n "$POD" ] && kubectl -n windbg port-forward --address 127.0.0.1 "$POD" 2222:22
  sleep 5
done
