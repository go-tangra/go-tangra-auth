//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// secretPatterns must never appear in logs, audit details, outbox payloads
// (at rest) or error bodies.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\$argon2id\$`),          // password hashes
	regexp.MustCompile(`otpauth://`),            // TOTP seeds
	regexp.MustCompile(`__Host-session=`),       // session cookies
	regexp.MustCompile(`eyJhbGciOiJFZERTQSI`),   // EdDSA JWT header
	regexp.MustCompile(`-----BEGIN`),            // PEM keys
	regexp.MustCompile(`"password":"[^"]{4,}"`), // raw passwords in JSON
	regexp.MustCompile(`\+38591`),               // the profile phone number (feature 004, PII)
}

// TestRedactionScan drives the sensitive flows, then scans every sink the
// service writes to. FREYA_CAPTURE_DIR (set by scripts/redaction-scan.sh)
// receives a copy of the captured artefacts for the shell scanner.
func TestRedactionScan(t *testing.T) {
	e := Start(t)
	tid, _ := e.Seed("acme", "alice@acme.test", pw, "")
	e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "alice@acme.test", "password": "wrong-password"})
	e.SignIn("acme", "alice@acme.test", pw)
	e.JSON(http.MethodPost, "/api/v1/session/token", nil)
	e.JSON(http.MethodPost, "/api/v1/me/mfa/enroll", nil)
	e.JSON(http.MethodPost, "/api/v1/recovery", map[string]string{"tenant": "acme", "email": "alice@acme.test"})
	e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "alice@acme.test", "password": "{\"password\":\"injected\"}"})
	// Feature 004: a phone number saved on the profile must never reach a sink.
	e.JSON(http.MethodPut, "/api/v1/me/profile", map[string]string{"first_name": "Alice", "last_name": "Scanner", "phone": "+385911234567"})
	e.JSON(http.MethodGet, "/api/v1/session", nil)
	e.JSON(http.MethodPost, "/api/v1/session/token", nil)
	// Sinks: application audit details, outbox payloads at rest, error bodies.
	var blobs []string
	err := e.App.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), "SELECT details::text FROM auth_audit_events WHERE tenant_id = $1", tid)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				return err
			}
			blobs = append(blobs, "audit:"+d)
		}
		rows2, err := tx.Query(context.Background(), "SELECT encode(payload_enc, 'escape') FROM outbox")
		if err != nil {
			return err
		}
		defer rows2.Close()
		for rows2.Next() {
			var p string
			if err := rows2.Scan(&p); err != nil {
				return err
			}
			blobs = append(blobs, "outbox:"+p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	code, out := e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "alice@acme.test", "password": "another-wrong"})
	if code != 401 {
		t.Fatal(code)
	}
	for k, v := range out {
		blobs = append(blobs, "error:"+k+"="+strings.TrimSpace(strings.Join(strings.Fields(strings.ReplaceAll(strings.ReplaceAll(fmtAny(v), "\n", " "), "\r", " ")), " ")))
	}
	for _, b := range blobs {
		for _, re := range secretPatterns {
			if re.MatchString(b) {
				t.Errorf("secret pattern %q found in %s", re, b[:min(len(b), 80)])
			}
		}
	}
	if dir := os.Getenv("FREYA_CAPTURE_DIR"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "sinks.txt"), []byte(strings.Join(blobs, "\n")), 0o600)
	}
}

func fmtAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
