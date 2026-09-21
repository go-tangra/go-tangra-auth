#!/usr/bin/env bash
# SC: no password hashes, TOTP seeds, cookies, tokens or keys in any captured output.
set -euo pipefail
ART="${ARTIFACTS:-.artifacts}"; export FREYA_CAPTURE_DIR="$ART/capture"; mkdir -p "$FREYA_CAPTURE_DIR"
go test -count=1 -tags integration ./tests/integration/... -run 'Test' -v > "$ART/integration.log" 2>&1 || { tail -50 "$ART/integration.log"; exit 1; }
cp "$ART/integration.log" "$FREYA_CAPTURE_DIR/suite.log"
# '+38591' is the phone prefix every integration fixture uses (feature 004): it must never be captured.
n=0; for pat in '-----BEGIN' '\$argon2id\$' 'otpauth://' '__Host-session=' 'eyJhbGciOiJFZERTQSI' '+38591'; do
  c=$({ grep -rc -- "$pat" "$FREYA_CAPTURE_DIR" || true; } | awk -F: '{s+=$2} END {print s+0}'); echo "redaction-scan: '$pat': $c"; n=$((n+c)); done
[[ "$n" -eq 0 ]] || { echo "redaction-scan: FAIL ($n matches)" >&2; exit 1; }; echo "redaction-scan: 0 matches"
