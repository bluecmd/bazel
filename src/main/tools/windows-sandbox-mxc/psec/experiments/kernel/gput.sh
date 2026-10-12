#!/bin/bash
# gput.sh <local> <remote path like C:/kd/x>
PW=$(kubectl -n windbg get secret kdt-sysprep -o jsonpath='{.data.password}' | base64 -d)
for i in 1 2 3 4 5 6; do
  out=$(sshpass -p "$PW" scp -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20 "$1" "debug@127.0.0.1:$2" 2>&1); rc=$?
  if [ $rc -eq 0 ]; then exit 0; fi
  sleep 4
done
echo "$out"; exit 0
