#!/usr/bin/env bash
# SC: no password hashes, TOTP seeds, cookies, tokens or keys in any captured output.
# Feature 016 (LDAP import): the ldapdir/directory tests drive every path with
# the sentinel bind password LDAP-MARKER-PW-* against a directory that echoes
# it, and write what they observed (responses, errors, logs, audit rows) to
# $FREYA_CAPTURE_DIR; the suite log is captured as well.
set -euo pipefail
ART="${ARTIFACTS:-.artifacts}"; export FREYA_CAPTURE_DIR="$ART/capture"; mkdir -p "$FREYA_CAPTURE_DIR"
go test -count=1 -tags integration ./tests/integration/... -run 'Test' -v > "$ART/integration.log" 2>&1 || { tail -50 "$ART/integration.log"; exit 1; }
cp "$ART/integration.log" "$FREYA_CAPTURE_DIR/suite.log"
go test -count=1 ./internal/ldapdir/... ./internal/directory/... -v > "$ART/ldap.log" 2>&1 || { tail -50 "$ART/ldap.log"; exit 1; }
cp "$ART/ldap.log" "$FREYA_CAPTURE_DIR/ldap-suite.log"
# '+38591' is the phone prefix every integration fixture uses (feature 004): it must never be captured.
n=0; for pat in '-----BEGIN' '\$argon2id\$' 'otpauth://' '__Host-session=' 'eyJhbGciOiJFZERTQSI' '+38591' 'LDAP-MARKER-PW-[A-Za-z0-9]'; do
  c=$({ grep -rc -- "$pat" "$FREYA_CAPTURE_DIR" || true; } | awk -F: '{s+=$2} END {print s+0}'); echo "redaction-scan: '$pat': $c"; n=$((n+c)); done
[[ "$n" -eq 0 ]] || { echo "redaction-scan: FAIL ($n matches)" >&2; exit 1; }; echo "redaction-scan: 0 matches"
