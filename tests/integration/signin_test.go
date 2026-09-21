//go:build integration

package integration

import (
	"net/http"
	"testing"
)

const pw = "correct horse battery staple"

func TestSigninMatrix(t *testing.T) {
	e := Start(t)
	acme, _ := e.Seed("acme", "alice@acme.test", pw, `{"lockout_threshold":5}`)
	e.Seed("globex", "bob@globex.test", pw, "")
	frozen, _ := e.Seed("frozen", "carol@frozen.test", pw, "")
	e.SetTenantStatus(frozen, "suspended")
	cases := map[string]map[string]string{
		"unknown tenant":   {"tenant": "nope", "email": "alice@acme.test", "password": pw},
		"unknown email":    {"tenant": "acme", "email": "zed@acme.test", "password": pw},
		"wrong password":   {"tenant": "acme", "email": "alice@acme.test", "password": "wrong"},
		"suspended tenant": {"tenant": "frozen", "email": "carol@frozen.test", "password": pw},
		"cross tenant":     {"tenant": "globex", "email": "alice@acme.test", "password": pw},
	}
	for name, body := range cases {
		code, out := e.JSON(http.MethodPost, "/api/v1/signin", body)
		if code != 401 || out["reason"] != "invalid_credentials" || len(out) != 1 {
			t.Fatalf("%s → %d %v", name, code, out)
		}
		if e.sessionCookie() != "" {
			t.Fatalf("%s: no session cookie may be issued on failure", name)
		}
	}
	if code, out := e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "alice@acme.test", "password": pw}); code != 200 || out["signed_in"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := e.JSON(http.MethodGet, "/api/v1/session", nil); code != 200 || out["tenant"].(map[string]any)["slug"] != "acme" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := e.JSON(http.MethodPost, "/api/v1/signout", nil); code != 204 {
		t.Fatal("signout")
	}
	// Lockout after the tenant threshold, then 423 even with the right password.
	for i := 0; i < 5; i++ {
		e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "alice@acme.test", "password": "wrong"})
	}
	if code, out := e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "alice@acme.test", "password": pw}); code != 423 || out["reason"] != "locked" {
		t.Fatalf("%d %v", code, out)
	}
	// Per-origin rate limit.
	for i := 0; i < 70; i++ {
		e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "nobody@acme.test", "password": "x"})
	}
	if code, out := e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "nobody@acme.test", "password": "x"}); code != 429 || out["reason"] != "rate_limited" {
		t.Fatalf("%d %v", code, out)
	}
	// Audit: one signin_failed per refused known-account attempt, one lockout.
	if n := e.AuditCount(acme, "lockout"); n != 1 {
		t.Fatalf("lockout rows %d", n)
	}
	if n := e.AuditCount(acme, "signin_failed"); n < 7 {
		t.Fatalf("signin_failed rows %d", n)
	}
	if n := e.AuditCount(acme, "signin_ok"); n != 1 {
		t.Fatalf("signin_ok rows %d", n)
	}
}
