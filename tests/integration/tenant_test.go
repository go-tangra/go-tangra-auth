//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestTenantLifecycle: quickstart §2–§3 and §9 — operator creates a tenant,
// the owner accepts, suspension kills every session, reactivation restores
// sign-in, and tenant admins cannot reach operator endpoints.
func TestTenantLifecycle(t *testing.T) {
	e := Start(t)
	res, err := e.App.Bootstrap(t.Context(), "ops@example.org")
	if err != nil {
		t.Fatal(err)
	}
	mail := e.LastMail("ops@example.org")
	tok := strings.TrimSpace(strings.Split(mail[strings.Index(mail, "token=")+6:], "\n")[0])
	op := e.Browser()
	if code, out := op.JSON(http.MethodPost, "/api/v1/invitations/accept", map[string]string{"token": tok, "display_name": "Ops", "password": "operator-password-1"}); code != 200 || out["mfa_setup_required"] != true {
		t.Fatalf("%d %v", code, out)
	}
	_ = res
	code, out := op.JSON(http.MethodPost, "/api/v1/operator/tenants", map[string]string{"slug": "acme", "display_name": "Acme", "owner_email": "owner@acme.test"})
	if code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	tid := out["tenant"].(map[string]any)["id"].(string)
	mail = e.LastMail("owner@acme.test")
	tok = strings.TrimSpace(strings.Split(mail[strings.Index(mail, "token=")+6:], "\n")[0])
	owner := e.Browser()
	if code, _ := owner.JSON(http.MethodPost, "/api/v1/invitations/accept", map[string]string{"token": tok, "display_name": "Owner", "password": "owner-password-1"}); code != 200 {
		t.Fatal(code)
	}
	if code, _ := owner.JSON(http.MethodGet, "/api/v1/operator/tenants", nil); code != 403 {
		t.Fatalf("tenant admin on operator endpoint → %d", code)
	}
	if code, _ := owner.JSON(http.MethodPost, "/api/v1/admin/invitations", map[string]any{"email": "user@acme.test"}); code != 202 {
		t.Fatal(code)
	}
	// Suspend: owner session dead within 10 s, sign-in refused.
	if code, _ := op.JSON(http.MethodPost, "/api/v1/operator/tenants/"+tid+"/suspend", nil); code != 204 {
		t.Fatal(code)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, _ = owner.JSON(http.MethodGet, "/api/v1/session", nil)
		if code == 401 || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if code != 401 {
		t.Fatal("owner session survived suspension")
	}
	if code, out := owner.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "owner@acme.test", "password": "owner-password-1"}); code != 401 || out["reason"] != "invalid_credentials" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := op.JSON(http.MethodPost, "/api/v1/operator/tenants/"+tid+"/reactivate", nil); code != 204 {
		t.Fatal(code)
	}
	if owner.SignIn("acme", "owner@acme.test", "owner-password-1") != 200 {
		t.Fatal("sign-in after reactivation")
	}
	for event, want := range map[string]int{"tenant_created": 1, "tenant_suspended": 1, "tenant_reactivated": 1} {
		if n := e.AuditCount(tid, event); n != want {
			t.Errorf("%s: %d", event, n)
		}
	}
}
