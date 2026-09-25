//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAdminFlows(t *testing.T) {
	e := Start(t)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	if code := e.SignIn("acme", "owner@acme.test", pw); code != 200 {
		t.Fatal(code)
	}
	// Invite → mail → accept → signed in with the invited role.
	if code, _ := e.JSON(http.MethodPost, "/api/v1/admin/invitations", map[string]any{"email": "new@acme.test", "role_ids": []string{roles["auditor"]}}); code != 202 {
		t.Fatal(code)
	}
	mail := e.LastMail("new@acme.test")
	if r := e.LastSend("new@acme.test"); r.GetTemplateKey() != "auth.invite" || r.GetTenantId() != tid || r.GetVariables()["valid_for"] != "72 hours" || r.GetVariables()["tenant"] == "" {
		t.Fatalf("invitation send %+v", r)
	}
	tok := strings.TrimSpace(mail[strings.Index(mail, "token=")+6:])
	if i := strings.IndexAny(tok, "\r\n "); i > 0 {
		tok = tok[:i]
	}
	nb := e.Browser()
	code, out := nb.JSON(http.MethodPost, "/api/v1/invitations/accept", map[string]string{"token": tok, "display_name": "New", "password": "a-long-enough-password"})
	if code != 200 || out["signed_in"] != true {
		t.Fatalf("%d %v", code, out)
	}
	code, out = nb.JSON(http.MethodGet, "/api/v1/session", nil)
	if code != 200 || out["roles"].([]any)[0] != "auditor" {
		t.Fatalf("%d %v", code, out)
	}
	newID := out["user"].(map[string]any)["id"].(string)
	// Assign admin → the next token carries it; revoke → gone.
	if code, _ := e.JSON(http.MethodPut, "/api/v1/admin/users/"+newID+"/roles", map[string]any{"role_ids": []string{roles["admin"]}}); code != 200 {
		t.Fatal(code)
	}
	nb.JSON(http.MethodPost, "/api/v1/signout", nil)
	if code := nb.SignIn("acme", "new@acme.test", "a-long-enough-password"); code != 200 {
		t.Fatal(code)
	}
	_, out = nb.JSON(http.MethodPost, "/api/v1/session/token", nil)
	v := e.Verifier(nil)
	id, err := v.Verify(context.Background(), out["access_token"].(string))
	if err != nil || len(id.Roles) != 1 || id.Roles[0] != "admin" {
		t.Fatalf("%+v %v", id, err)
	}
	if code, _ := e.JSON(http.MethodPut, "/api/v1/admin/users/"+newID+"/roles", map[string]any{"role_ids": []string{}}); code != 200 {
		t.Fatal(code)
	}
	// Deactivate: sessions dead within 10 s, sign-in refused; reactivate restores sign-in.
	if code, _ := e.JSON(http.MethodPost, "/api/v1/admin/users/"+newID+"/deactivate", nil); code != 204 {
		t.Fatal(code)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, _ = nb.JSON(http.MethodGet, "/api/v1/session", nil)
		if code == 401 || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if code != 401 {
		t.Fatal("session survived deactivation")
	}
	if code := nb.SignIn("acme", "new@acme.test", "a-long-enough-password"); code != 401 {
		t.Fatalf("deactivated sign-in → %d", code)
	}
	if code, _ := e.JSON(http.MethodPost, "/api/v1/admin/users/"+newID+"/reactivate", nil); code != 204 {
		t.Fatal(code)
	}
	if code := nb.SignIn("acme", "new@acme.test", "a-long-enough-password"); code != 200 {
		t.Fatalf("reactivated sign-in → %d", code)
	}
	// Force sign-out.
	if code, _ := e.JSON(http.MethodPost, "/api/v1/admin/users/"+newID+"/sessions/revoke", nil); code != 204 {
		t.Fatal(code)
	}
	if code, _ := nb.JSON(http.MethodGet, "/api/v1/session", nil); code != 401 {
		t.Fatal("force sign-out")
	}
	// Each step audited exactly once (two revocations: auditor when admin was
	// assigned, admin when the roles were cleared).
	for event, want := range map[string]int{"invite_created": 1, "invite_accepted": 1, "role_assigned": 1, "role_revoked": 2, "user_deactivated": 1, "user_reactivated": 1} {
		if n := e.AuditCount(tid, event); n != want {
			t.Errorf("%s: %d rows, want %d", event, n, want)
		}
	}
}
