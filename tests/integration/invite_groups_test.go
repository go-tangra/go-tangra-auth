//go:build integration

package integration

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/authz"
)

// TestInviteIntoGroups: quickstart §5 — an invitation names a group and
// names; acceptance joins the group (its roles apply) and fills the profile;
// a group deleted before acceptance is skipped.
func TestInviteIntoGroups(t *testing.T) {
	e := Start(t)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	_, _ = e.App.Registry.Register(svcCtx(), tid, "svc", []authz.Permission{{Resource: "invoices", Action: "read"}})
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	_, reader := e.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": "reader", "display_name": "R", "permissions": []string{"invoices:read"}})
	_, fin := e.JSON(http.MethodPost, "/api/v1/admin/groups", map[string]any{"name": "Finance"})
	_, tmp := e.JSON(http.MethodPost, "/api/v1/admin/groups", map[string]any{"name": "Temporary"})
	e.JSON(http.MethodPut, "/api/v1/admin/groups/"+fin["id"].(string)+"/roles", map[string]any{"role_ids": []string{reader["id"].(string)}})
	if code, out := e.JSON(http.MethodPost, "/api/v1/admin/invitations", map[string]any{"email": "dana@acme.test", "group_ids": []string{fin["id"].(string), tmp["id"].(string)}, "first_name": "Dana", "last_name": "Kovač"}); code != 202 {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := e.JSON(http.MethodPost, "/api/v1/admin/groups/"+tmp["id"].(string)+"/remove", map[string]any{"member_count": 0}); code != 204 {
		t.Fatal(code)
	}
	mail := e.LastMail("dana@acme.test")
	tok := regexp.MustCompile(`token=([A-Za-z0-9_-]+)`).FindStringSubmatch(mail)
	if tok == nil {
		t.Fatalf("no token in mail: %q", mail)
	}
	b := e.Browser()
	code, acc := b.JSON(http.MethodPost, "/api/v1/invitations/accept", map[string]string{"token": tok[1], "display_name": "", "password": "a-long-enough-password"})
	if code != 200 || acc["roles"].([]any)[0] != "reader" {
		t.Fatalf("%d %v", code, acc)
	}
	_, sess := b.JSON(http.MethodGet, "/api/v1/session", nil)
	if sess["user"].(map[string]any)["display_name"] != "Dana Kovač" {
		t.Fatalf("profile from invitation: %v", sess)
	}
	uid := sess["user"].(map[string]any)["id"].(string)
	if d, _ := e.App.Decider.Decide(svcCtx(), tid, uid, authz.PermissionRef{Resource: "invoices", Action: "read"}); !d.Allowed {
		t.Fatalf("group role must apply: %+v", d)
	}
	_, groups := e.JSON(http.MethodGet, "/api/v1/admin/users/"+uid+"/groups", nil)
	if items := groups["items"].([]any); len(items) != 1 || items[0].(map[string]any)["name"] != "Finance" {
		t.Fatalf("groups %v", groups)
	}
}
