#!/usr/bin/env bash
# Service coverage gate: >=80% overall, 100% for the security-critical packages.
set -euo pipefail
PROFILE="${1:-coverage.out}"
MODULE="github.com/go-tangra/go-tangra-auth/v4"
SECURITY_PKGS=("internal/token" "internal/session" "internal/password" "internal/mfa" "internal/tenantctx" "internal/ldapdir")
total=$(go tool cover -func="$PROFILE" | awk '/^total:/ {gsub("%","",$3); print $3}')
echo "coverage: total ${total}%"
fail=0
awk -v t="$total" 'BEGIN { if (t+0 < 80) exit 1 }' || { echo "coverage: total below 80%" >&2; fail=1; }
for p in "${SECURITY_PKGS[@]}"; do
  pct=$(go tool cover -func="$PROFILE" | awk -v pre="$MODULE/$p/" '
    index($1, pre)==1 { rest=substr($1, length(pre)+1); if (rest ~ /\//) next
      if ($1 ~ /doc\.go/) next; gsub("%","",$3); s+=$3; n++ }
    END { if (n==0) print "n/a"; else printf "%.1f", s/n }')
  echo "coverage: $p ${pct}%"
  if [[ "$pct" != "n/a" ]]; then awk -v v="$pct" 'BEGIN { if (v+0 < 100) exit 1 }' || { echo "coverage: $p must be 100%" >&2; fail=1; }; fi
done
exit $fail
