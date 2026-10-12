#!/bin/bash
# gget.sh <remote path> <local>
PW=$(kubectl -n windbg get secret kdt-sysprep -o jsonpath='{.data.password}' | base64 -d)
sshpass -p "$PW" scp -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "debug@127.0.0.1:$1" "$2" 2>&1; exit 0
