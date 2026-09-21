package httpapi

import (
	"os"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/audit"
)

// TestAdminProfileHandlers: administrators read and edit any profile of their
// tenant (phone included), remove avatars, and find people by name; members
// are refused and other tenants are not found.
func TestAdminProfileHandlers(t *testing.T) {
	u := newUS1(t)
	aw := withProfiles(t, u)
	defer aw.Close()
	ow, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	owner := sessionCookie(ow)
	bw, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`)
	bob := sessionCookie(bw)

	if w, out := u.call("GET", "/api/v1/admin/users/u1/profile", "", bob); w.Code != 403 || out["reason"] != "forbidden" {
		t.Fatalf("member -> %d %v", w.Code, out)
	}
	w, out := u.call("PUT", "/api/v1/admin/users/u2/profile", `{"first_name":"Robert","last_name":"Kovac","phone":"+1 415 555 0100"}`, owner)
	if w.Code != 200 || out["first_name"] != "Robert" || out["phone"] != "+14155550100" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w.Header().Get(IdentityRefreshHeader) != "" {
		t.Fatal("editing someone else must not claim the caller's identity changed")
	}
	if w, out := u.call("GET", "/api/v1/admin/users/u2/profile", "", owner); w.Code != 200 || out["phone"] != "+14155550100" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// The subject sees the change on their next request.
	if w, out := u.call("GET", "/api/v1/me/profile", "", bob); w.Code != 200 || out["first_name"] != "Robert" {
		t.Fatalf("subject view %d %v", w.Code, out)
	}
	// Search by last name; the listing carries the avatar address.
	png, _ := os.ReadFile("../../tests/fuzz/testdata/avatars/valid.png")
	if w := u.raw("PUT", "/api/v1/me/avatar", png, "image/png", bob); w.Code != 200 {
		t.Fatalf("upload %d", w.Code)
	}
	w, out = u.call("GET", "/api/v1/admin/users?q=kovac", "", owner)
	items := out["items"].([]any)
	if w.Code != 200 || len(items) != 1 || items[0].(map[string]any)["avatar_url"] == "" || items[0].(map[string]any)["phone"] != nil {
		t.Fatalf("search %d %v", w.Code, out)
	}
	if w := u.raw("DELETE", "/api/v1/admin/users/u2/avatar", nil, "", owner); w.Code != 204 {
		t.Fatalf("admin remove -> %d", w.Code)
	}
	if w, out := u.call("GET", "/api/v1/me/profile", "", bob); out["avatar_url"] != "" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Cross-tenant and unknown ids are not found; validation applies to admins too.
	if w, out := u.call("PUT", "/api/v1/admin/users/u9/profile", `{"first_name":"X"}`, owner); w.Code != 404 || out["reason"] != "not_found" {
		t.Fatalf("foreign -> %d %v", w.Code, out)
	}
	if w, out := u.call("PUT", "/api/v1/admin/users/u2/profile", `{"phone":"nope"}`, owner); w.Code != 400 || out["reason"] != "invalid_phone" {
		t.Fatalf("%d %v", w.Code, out)
	}
	aw.Flush()
	var adminEdits int
	for _, r := range u.ms.AuditRows {
		if r.EventType == string(audit.ProfileUpdated) && r.Outcome == "ok" && r.SubjectID != nil && *r.SubjectID == "u2" && r.ActorUserID != nil && *r.ActorUserID == "u1" {
			adminEdits++
		}
	}
	if adminEdits != 1 {
		t.Fatalf("admin edit must be audited with actor=admin subject=user: %d", adminEdits)
	}
}
