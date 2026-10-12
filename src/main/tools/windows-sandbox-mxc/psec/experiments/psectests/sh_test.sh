#!/bin/bash
set -euo pipefail
echo "TEST_TMPDIR=$TEST_TMPDIR shell=$0"
f=$(grep '^_main/psectests/data.txt ' "$RUNFILES_MANIFEST_FILE" | cut -d' ' -f2-)
cat "$f"
echo x > "$TEST_TMPDIR/t.txt"
echo PASS
