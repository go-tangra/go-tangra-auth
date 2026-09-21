#!/usr/bin/env bash
# SC-005 gate: BenchmarkCheck p95 must stay below 20 ms at 1,000 concurrency.
# Requires Docker (testcontainers). Usage: scripts/authz-gate.sh [max_p95_ms]
set -euo pipefail
max="${1:-20}"
out=$(go test -tags integration -run '^$' -bench '^BenchmarkCheck$' -benchtime=20000x ./tests/integration/ 2>&1)
echo "$out"
p95=$(echo "$out" | awk '/p95_ms/ { for (i = 1; i <= NF; i++) if ($i == "p95_ms") print $(i-1) }' | tail -1)
if [ -z "$p95" ]; then
  echo "authz-gate: no p95_ms metric reported" >&2
  exit 1
fi
awk -v p="$p95" -v m="$max" 'BEGIN { if (p + 0 > m + 0) { printf "authz-gate: p95 %.2f ms exceeds %.2f ms\n", p, m; exit 1 } else { printf "authz-gate: p95 %.2f ms within %.2f ms\n", p, m } }'
