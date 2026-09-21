//go:build integration

package integration

import (
	"context"
	"net/http"
	"os"
	"testing"
)

// TestAdminProfile: quickstart §4 — an administrator edits another person's
// profile and removes their avatar; the person sees it on their next request
// (their cached session view is evicted), the audit event names actor and
// subject, and members are refused.
func TestAdminProfile(t *testing.T) {
	e := Start(t)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	_, dana := e.Seed("acme", "dana@acme.test", pw, "")
	e.Bind(tid, dana, roles)
	db := e.Browser()
	if db.SignIn("acme", "dana@acme.test", pw) != 200 {
		t.Fatal("dana sign-in")
	}
	png, _ := os.ReadFile("../fuzz/testdata/avatars/valid.png")
	if code, _, _ := db.upload("/api/v1/me/avatar", png, "image/png"); code != 200 {
		t.Fatalf("upload %d", code)
	}
	// A member cannot touch another profile.
	if code, out := db.JSON(http.MethodPut, "/api/v1/admin/users/"+owner+"/profile", map[string]string{"first_name": "X"}); code != 403 || out["reason"] != "forbidden" {
		t.Fatalf("member -> %d %v", code, out)
	}
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("owner sign-in")
	}
	code, out := e.JSON(http.MethodPut, "/api/v1/admin/users/"+dana+"/profile", map[string]string{"first_name": "Dana", "last_name": "Kovač", "phone": "+385 91 123 4567"})
	if code != 200 || out["display_name"] != "Dana Kovač" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := e.JSON(http.MethodDelete, "/api/v1/admin/users/"+dana+"/avatar", nil); code != 204 {
		t.Fatalf("admin avatar remove -> %d", code)
	}
	// Dana's next request (and her next token) carry the new attributes.
	_, sess := db.JSON(http.MethodGet, "/api/v1/session", nil)
	u := sess["user"].(map[string]any)
	if u["display_name"] != "Dana Kovač" || u["avatar_url"] != "" {
		t.Fatalf("subject session %v", sess)
	}
	a, err := e.App.Sessions.ByID(context.Background(), tid, sessionIDOf(t, db))
	if err != nil || a.DisplayName != "Dana Kovač" || a.AvatarURL != "" {
		t.Fatalf("identity %+v %v", a, err)
	}
	// Search by name; audit actor/subject.
	_, list := e.JSON(http.MethodGet, "/api/v1/admin/users?q=kova", nil)
	if items := list["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != dana {
		t.Fatalf("search %v", list)
	}
	if n := e.AuditCount(tid, "profile_updated"); n < 1 {
		t.Fatalf("profile_updated %d", n)
	}
	if n := e.AuditCount(tid, "avatar_removed"); n != 1 {
		t.Fatalf("avatar_removed %d", n)
	}
}
