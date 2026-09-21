//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/go-freya/freya/services/auth/internal/store"
)

// TestCrossTenantMatrix: SC-002 — every cross-tenant attempt by guessed id is
// refused (403/404), audited, and impossible at the SQL layer (RLS).
func TestCrossTenantMatrix(t *testing.T) {
	e := Start(t)
	tA, ownerA := e.Seed("acme", "owner@acme.test", pw, "")
	tB, ownerB := e.Seed("globex", "owner@globex.test", pw, "")
	rolesA, rolesB := e.SeedRoles(tA), e.SeedRoles(tB)
	e.Bind(tA, ownerA, rolesA, "owner")
	e.Bind(tB, ownerB, rolesB, "owner")
	a, b := e.Browser(), e.Browser()
	if a.SignIn("acme", "owner@acme.test", pw) != 200 || b.SignIn("globex", "owner@globex.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	_, sess := a.JSON(http.MethodGet, "/api/v1/session", nil)
	sidA := sess["session_id"].(string)
	// B against A's user, roles, session and (later stories) policy/audit are 404/403.
	for _, c := range []struct {
		method, path string
		body         any
		want         int
	}{
		{http.MethodPut, "/api/v1/admin/users/" + ownerA + "/roles", map[string]any{"role_ids": []string{rolesB["admin"]}}, 404},
		{http.MethodPost, "/api/v1/admin/users/" + ownerA + "/deactivate", nil, 404},
		{http.MethodPost, "/api/v1/admin/users/" + ownerA + "/sessions/revoke", nil, 404},
		{http.MethodPost, "/api/v1/sessions/" + sidA + "/revoke", nil, 404},
		{http.MethodPut, "/api/v1/admin/users/" + ownerB + "/roles", map[string]any{"role_ids": []string{rolesA["admin"]}}, 404},
	} {
		if code, _ := b.JSON(c.method, c.path, c.body); code != c.want {
			t.Errorf("%s %s → %d, want %d", c.method, c.path, code, c.want)
		}
	}
	// A's session is untouched; B's listing never shows A's users.
	if code, _ := a.JSON(http.MethodGet, "/api/v1/session", nil); code != 200 {
		t.Fatal("A's session affected")
	}
	if _, out := b.JSON(http.MethodGet, "/api/v1/admin/users", nil); len(out["items"].([]any)) != 1 {
		t.Fatalf("B sees %v", out["items"])
	}
	// A token from tenant A is not accepted as B's user (tenant-pinned verifier).
	_, tokOut := a.JSON(http.MethodPost, "/api/v1/session/token", nil)
	v := e.Verifier(nil)
	id, err := v.Verify(context.Background(), tokOut["access_token"].(string))
	if err != nil || id.TenantID != tA {
		t.Fatalf("%+v %v", id, err)
	}
	// Audit rows for the refusals land in B's trail (the actor's tenant).
	if n := e.AuditCount(tB, "cross_tenant_refused"); n < 3 {
		t.Fatalf("cross_tenant_refused rows in B: %d", n)
	}
	// RLS: with app.tenant_id = B nothing of A is visible, even with direct SQL.
	err = e.App.Store.Tx(context.Background(), store.Scope{TenantID: tB}, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(context.Background(), "SELECT count(*) FROM users WHERE tenant_id = $1", tA).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("RLS leak: %d users of A visible to B", n)
		}
		if err := tx.QueryRow(context.Background(), "SELECT count(*) FROM sessions WHERE tenant_id = $1", tA).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("RLS leak: %d sessions of A visible to B", n)
		}
		_, err := tx.Exec(context.Background(), "UPDATE users SET status = 'deactivated' WHERE id = $1", ownerA)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := a.JSON(http.MethodGet, "/api/v1/session", nil); code != 200 {
		t.Fatal("A's owner must be untouched by B's UPDATE")
	}
}
