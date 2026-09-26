//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-auth/v4/internal/config"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/webauthn/softkey"
)

// TestSecurityKeyEndToEnd (feature 018, T021): register a key, sign out, sign
// in with password + key against PostgreSQL and Valkey; the session and the
// audit record amr pwd,hwk; ceremonies are single use; rename and removal
// work on the stored rows. The harness issuer is an IP address, so the
// relying party is set explicitly (keys are bound to a host name).
func TestSecurityKeyEndToEnd(t *testing.T) {
	const origin = "https://localhost"
	on := true
	e := Start(t, func(c *config.Config, _ string) {
		c.WebAuthn.Enabled, c.WebAuthn.RPID, c.WebAuthn.Origins = &on, "localhost", []string{origin}
	})
	ctx := context.Background()
	const em, pw = "keys@keys.test", "a-long-enough-password"
	tid, uid := e.Seed("keys", em, pw, `{"lockout_threshold":5,"lockout_duration":"5m"}`)
	if code := e.SignIn("keys", em, pw); code != 200 {
		t.Fatalf("sign in → %d", code)
	}
	key := softkey.New(origin)
	opts := e.raw(t, http.MethodPost, "/api/v1/me/mfa/webauthn/register/options", map[string]any{"name": "YubiKey desk"}, 200)
	resp, err := key.Create(opts)
	if err != nil {
		t.Fatal(err)
	}
	code, out := e.JSON(http.MethodPost, "/api/v1/me/mfa/webauthn/register", map[string]any{"credential": json.RawMessage(resp)})
	if code != 201 || len(out["recovery_codes"].([]any)) != 10 {
		t.Fatalf("register → %d %v", code, out)
	}
	keyID := out["key"].(map[string]any)["id"].(string)
	// The row, the user handle and the second-step flag are stored.
	var handle []byte
	var enabled bool
	var n int
	if err := e.App.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT webauthn_handle, mfa_enabled FROM users WHERE id=$1", uid).Scan(&handle, &enabled); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT count(*) FROM webauthn_credentials WHERE user_id=$1 AND credential_id=$2", uid, key.ID).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if len(handle) != 32 || !enabled || n != 1 {
		t.Fatalf("handle %d enabled %v rows %d", len(handle), enabled, n)
	}
	if code, _ := e.JSON(http.MethodPost, "/api/v1/signout", nil); code != 204 {
		t.Fatalf("signout → %d", code)
	}

	// Password, then the key.
	code, out = e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "keys", "email": em, "password": pw})
	if code != 200 || out["mfa_required"] != true || !strings.Contains(strings.Join(anyStrings(out["mfa_methods"]), ","), "webauthn") {
		t.Fatalf("signin → %d %v", code, out)
	}
	ch := out["challenge"].(string)
	req := e.raw(t, http.MethodPost, "/api/v1/signin/mfa/webauthn/options", map[string]any{"challenge": ch}, 200)
	assertion, err := key.Get(req)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"challenge": ch, "credential": json.RawMessage(assertion)}
	if code, out = e.JSON(http.MethodPost, "/api/v1/signin/mfa/webauthn", body); code != 200 || out["signed_in"] != true {
		t.Fatalf("key step → %d %v", code, out)
	}
	if code, out = e.JSON(http.MethodPost, "/api/v1/signin/mfa/webauthn", body); code != 401 {
		t.Fatalf("replayed step → %d %v", code, out)
	}
	code, out = e.JSON(http.MethodPost, "/api/v1/session/token", nil)
	if code != 200 {
		t.Fatalf("token → %d %v", code, out)
	}
	claims, _ := base64.RawURLEncoding.DecodeString(strings.Split(out["access_token"].(string), ".")[1])
	if !strings.Contains(string(claims), `"amr":["pwd","hwk"]`) {
		t.Fatalf("claims %s", claims)
	}
	if e.AuditCount(tid, "signin_ok") < 1 {
		t.Fatal("signin_ok not audited")
	}
	var details, enrolled string
	if err := e.App.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT details::text FROM auth_audit_events WHERE tenant_id=$1 AND event_type='signin_ok' ORDER BY ts DESC LIMIT 1", tid).Scan(&details); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT details::text FROM auth_audit_events WHERE tenant_id=$1 AND event_type='mfa_enrolled' LIMIT 1", tid).Scan(&enrolled)
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(details, `"hwk"`) || !strings.Contains(enrolled, `"webauthn"`) || strings.Contains(enrolled, base64.RawURLEncoding.EncodeToString(key.ID)) {
		t.Fatalf("audit details %s / %s", details, enrolled)
	}

	// Rename, then remove the key confirmed with the key itself.
	if code, out = e.JSON(http.MethodPatch, "/api/v1/me/mfa/webauthn/"+keyID, map[string]string{"name": "Office"}); code != 200 {
		t.Fatalf("rename → %d %v", code, out)
	}
	step := e.raw(t, http.MethodPost, "/api/v1/me/mfa/stepup/options", nil, 200)
	confirm, _ := key.Get(step)
	if code, out = e.JSON(http.MethodDelete, "/api/v1/me/mfa/webauthn/"+keyID, map[string]any{"credential": json.RawMessage(confirm)}); code != 204 {
		t.Fatalf("remove → %d %v", code, out)
	}
	code, out = e.JSON(http.MethodGet, "/api/v1/me/mfa", nil)
	if code != 200 || len(out["keys"].([]any)) != 0 || out["recovery_codes_left"].(float64) != 0 {
		t.Fatalf("after removal %d %v", code, out)
	}
}

// raw performs a JSON request and returns the body bytes (options documents).
func (e *Env) raw(t *testing.T, method, path string, body any, want int) []byte {
	t.Helper()
	code, out := e.JSON(method, path, body)
	if code != want {
		t.Fatalf("%s %s → %d %v", method, path, code, out)
	}
	b, _ := json.Marshal(out)
	return b
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
