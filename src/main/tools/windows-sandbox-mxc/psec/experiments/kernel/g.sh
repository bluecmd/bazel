#!/bin/bash
# g.sh "<windows command>": run it in the psec guest as the debug admin (retries while the forward restarts)
PW=$(kubectl -n windbg get secret kdt-sysprep -o jsonpath='{.data.password}' | base64 -d)
for i in 1 2 3 4 5 6; do
  out=$(sshpass -p "$PW" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20 debug@127.0.0.1 "$1" 2>&1); rc=$?
  if ! echo "$out" | grep -q -E 'Connection refused|Connection closed|kex_exchange|Connection reset'; then echo "$out"; exit 0; fi
  sleep 4
done
echo "$out"; exit 0
