//go:build integration

package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/go-freya/freya/services/auth/internal/store"
)

// TestUpgrade (SC-009): rows created before feature 004 keep working after the
// migration — the display name survives, an email-shaped display name is not
// treated as explicit, the session created before the profile columns were
// populated still resolves, and no re-sign-in is needed.
func TestUpgrade(t *testing.T) {
	e := Start(t)
	tid, alice := e.Seed("acme", "alice@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, alice, roles, "owner")
	// Simulate a pre-004 row: display name set by hand and the legacy email-shaped one.
	_, legacy := e.Seed("acme", "legacy@acme.test", pw, "")
	if err := e.App.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), "UPDATE users SET display_name = 'Alice Hand', display_name_explicit = true, first_name = '', last_name = '' WHERE id = $1", alice); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), "UPDATE users SET display_name = email, display_name_explicit = (display_name <> '' AND display_name <> email AND display_name <> split_part(email, '@', 1)) WHERE id = $1", legacy)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if e.SignIn("acme", "alice@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	// Existing display name is kept; setting names does not override a hand-set one.
	code, out := e.JSON(http.MethodPut, "/api/v1/me/profile", map[string]string{"first_name": "Alice", "last_name": "Kovač"})
	if code != 200 || out["display_name"] != "Alice Hand" {
		t.Fatalf("%d %v", code, out)
	}
	// The legacy user's email-shaped display name yields to the names.
	lb := e.Browser()
	if lb.SignIn("acme", "legacy@acme.test", pw) != 200 {
		t.Fatal("legacy sign-in")
	}
	code, out = lb.JSON(http.MethodPut, "/api/v1/me/profile", map[string]string{"first_name": "Old", "last_name": "Timer"})
	if code != 200 || out["display_name"] != "Old Timer" {
		t.Fatalf("%d %v", code, out)
	}
	// Sessions and tokens minted before the change keep working.
	if code, _ := e.JSON(http.MethodGet, "/api/v1/session", nil); code != 200 {
		t.Fatalf("session after upgrade → %d", code)
	}
	_, tok := e.JSON(http.MethodPost, "/api/v1/session/token", nil)
	if _, err := e.Verifier(nil).Verify(context.Background(), tok["access_token"].(string)); err != nil {
		t.Fatalf("token after upgrade: %v", err)
	}
}
