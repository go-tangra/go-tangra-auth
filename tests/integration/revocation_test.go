//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
)

// TestRevocationPropagation: SC-003 — force sign-out, deactivation and tenant
// suspension reach a downstream verifier within 10 s.
func TestRevocationPropagation(t *testing.T) {
	e := Start(t)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	v := e.Verifier(nil)
	mint := func(b *Env) string {
		_, out := b.JSON(http.MethodPost, "/api/v1/session/token", nil)
		return out["access_token"].(string)
	}
	observe := func(tok string) error {
		deadline := time.Now().Add(10 * time.Second)
		var err error
		for time.Now().Before(deadline) {
			_ = v.SyncRevocations(context.Background())
			if _, err = v.Verify(context.Background(), tok); errors.Is(err, authclient.ErrRevoked) {
				return nil
			}
			time.Sleep(250 * time.Millisecond)
		}
		return err
	}
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	// A second tenant's user whose tokens the verifier watches.
	_, carol := e.Seed("acme2", "carol@acme2.test", pw, "")
	cb := e.Browser()
	if cb.SignIn("acme2", "carol@acme2.test", pw) != 200 {
		t.Fatal("carol sign-in")
	}
	t1 := mint(cb)
	if _, err := v.Verify(context.Background(), t1); err != nil {
		t.Fatal(err)
	}
	// 1. Force sign-out through the session manager (what the admin route calls).
	if err := e.App.Sessions.RevokeUser(context.Background(), cb.tenantOf(t, t1, v), carol, session.ReasonAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if err := observe(t1); err != nil {
		t.Fatalf("force sign-out not observed: %v", err)
	}
	// 2. Deactivation. (Tokens carry second-granularity issue times: a token
	// minted in the same second as a user-wide revocation is still covered by
	// it, so the re-sign-in waits for the next second.)
	time.Sleep(1100 * time.Millisecond)
	if cb.SignIn("acme2", "carol@acme2.test", pw) != 200 {
		t.Fatal("re-sign-in")
	}
	t2 := mint(cb)
	if err := e.App.Sessions.RevokeUser(context.Background(), cb.tenantOf(t, t2, v), carol, session.ReasonDeactivated, ""); err != nil {
		t.Fatal(err)
	}
	if err := observe(t2); err != nil {
		t.Fatalf("deactivation not observed: %v", err)
	}
	// 3. Tenant suspension.
	time.Sleep(1100 * time.Millisecond)
	if cb.SignIn("acme2", "carol@acme2.test", pw) != 200 {
		t.Fatal("re-sign-in")
	}
	t3 := mint(cb)
	if err := e.App.Sessions.RevokeTenant(context.Background(), cb.tenantOf(t, t3, v), session.ReasonSuspended); err != nil {
		t.Fatal(err)
	}
	if err := observe(t3); err != nil {
		t.Fatalf("suspension not observed: %v", err)
	}
}

// tenantOf extracts the tenant id from a token (verifier already trusts it).
func (e *Env) tenantOf(t *testing.T, tok string, v *authclient.Verifier) string {
	t.Helper()
	id, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	return id.TenantID
}
