package httpapi

import (
	"strings"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/store"
)

func withGroups(t *testing.T, u *us1) (*audit.Writer, *authz.Client) {
	t.Helper()
	aw, ob := withUS2(t, u)
	u.outbox = ob
	c := cache.New(cache.NewMemory())
	az := authz.New(authz.NewFake(), c, nil)
	u.ms.AddUser(store.User{ID: "u3", TenantID: tid, Email: "dana@x.test", DisplayName: "Dana", Status: "active"})
	u.ms.AddUser(store.User{ID: "u9", TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99", Email: "f@x.test", Status: "active"})
	u.ms.RolePerms["r-auditor"] = [][2]string{{"audit", "read"}}
	u.srv.RegisterGroups(GroupDeps{Groups: authz.NewGroups(u.ms, az, aw)})
	return aw, az
}

func TestGroupHandlers(t *testing.T) {
	u := newUS1(t)
	aw, _ := withGroups(t, u)
	defer aw.Close()
	bw, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`)
	bob := sessionCookie(bw)
	ow, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	owner := sessionCookie(ow)

	// A plain member is refused (and audited); anonymous is unauthenticated.
	if w, out := u.call("GET", "/api/v1/admin/groups", "", bob); w.Code != 403 || out["reason"] != "forbidden" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/admin/groups", `{"name":"Finance"}`); w.Code != 401 {
		t.Fatalf("anonymous → %d", w.Code)
	}
	// Schema refusals come from the OpenAPI validator before any handler code.
	for _, body := range []string{`{"name":"` + strings.Repeat("x", 65) + `"}`, `{"name":""}`, `{"name":"ok","extra":1}`, `{}`} {
		if w, out := u.call("POST", "/api/v1/admin/groups", body, owner); w.Code != 400 || out["reason"] != "validation_failed" {
			t.Fatalf("%s → %d %v", body, w.Code, out)
		}
	}
	if w, out := u.call("POST", "/api/v1/admin/groups", "{\"name\":\"bad\\u0007name\"}", owner); w.Code != 400 || out["reason"] != "validation_failed" {
		t.Fatalf("control char → %d %v", w.Code, out)
	}
	// Create, duplicate, list, get.
	w, out := u.call("POST", "/api/v1/admin/groups", `{"name":" Finance ","description":"money"}`, owner)
	if w.Code != 201 || out["name"] != "Finance" || out["member_count"].(float64) != 0 {
		t.Fatalf("%d %v", w.Code, out)
	}
	gid := out["id"].(string)
	if w, out := u.call("POST", "/api/v1/admin/groups", `{"name":"finance"}`, owner); w.Code != 409 || out["reason"] != "name_taken" {
		t.Fatalf("duplicate → %d %v", w.Code, out)
	}
	w, out = u.call("GET", "/api/v1/admin/groups?q=fin", "", owner)
	if w.Code != 200 || len(out["items"].([]any)) != 1 {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("GET", "/api/v1/admin/groups/"+gid, "", owner); w.Code != 200 || out["name"] != "Finance" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("GET", "/api/v1/admin/groups/0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c00", "", owner); w.Code != 404 || out["reason"] != "not_found" {
		t.Fatalf("unknown → %d %v", w.Code, out)
	}
	// Roles then members; the member's effective roles name the group.
	if w, out := u.call("PUT", "/api/v1/admin/groups/"+gid+"/roles", `{"role_ids":["r-auditor"]}`, owner); w.Code != 200 || out["roles"].([]any)[0] != "auditor" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/admin/groups/"+gid+"/members", `{"user_ids":["u3","u2"]}`, owner); w.Code != 200 || out["added"].(float64) != 2 {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/admin/groups/"+gid+"/members", `{"user_ids":["u9"]}`, owner); w.Code != 404 || out["reason"] != "not_found" {
		t.Fatalf("foreign user → %d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/admin/groups/"+gid+"/members", `{"user_ids":[]}`, owner); w.Code != 400 {
		t.Fatalf("empty ids → %d", w.Code)
	}
	w, out = u.call("GET", "/api/v1/admin/groups/"+gid+"/members", "", owner)
	if w.Code != 200 || len(out["items"].([]any)) != 2 {
		t.Fatalf("%d %v", w.Code, out)
	}
	w, out = u.call("GET", "/api/v1/admin/users/u3/effective-roles", "", owner)
	if w.Code != 200 {
		t.Fatalf("%d %v", w.Code, out)
	}
	eff := out["items"].([]any)
	if len(eff) != 1 || eff[0].(map[string]any)["slug"] != "auditor" || eff[0].(map[string]any)["sources"].([]any)[0].(map[string]any)["group_name"] != "Finance" {
		t.Fatalf("effective %v", eff)
	}
	if w, out := u.call("GET", "/api/v1/admin/users/u3/groups", "", owner); w.Code != 200 || out["items"].([]any)[0].(map[string]any)["name"] != "Finance" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// The group shows in the user listing.
	w, out = u.call("GET", "/api/v1/admin/users?q=dana", "", owner)
	if w.Code != 200 || out["items"].([]any)[0].(map[string]any)["groups"].([]any)[0].(map[string]any)["name"] != "Finance" {
		t.Fatalf("user groups in listing: %d %v", w.Code, out)
	}
	// Remove a member (idempotent), rename, then delete with confirmation.
	if w, _ := u.call("POST", "/api/v1/admin/groups/"+gid+"/members/u2/remove", "", owner); w.Code != 204 {
		t.Fatalf("remove → %d", w.Code)
	}
	if w, _ := u.call("POST", "/api/v1/admin/groups/"+gid+"/members/u2/remove", "", owner); w.Code != 204 {
		t.Fatalf("remove again → %d", w.Code)
	}
	if w, out := u.call("PUT", "/api/v1/admin/groups/"+gid, `{"name":"Finance & Ops"}`, owner); w.Code != 200 || out["name"] != "Finance & Ops" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/admin/groups/"+gid+"/remove", `{"member_count":5}`, owner); w.Code != 409 || out["reason"] != "member_count_mismatch" {
		t.Fatalf("stale count → %d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/admin/groups/"+gid+"/remove", `{"member_count":1}`, owner); w.Code != 204 {
		t.Fatalf("delete → %d", w.Code)
	}
	if w, _ := u.call("GET", "/api/v1/admin/groups/"+gid, "", owner); w.Code != 404 {
		t.Fatalf("deleted → %d", w.Code)
	}
	// Escalation: bob (admin, no permissions in FGA) cannot grant audit:read via a group.
	if w, _ := u.call("PUT", "/api/v1/admin/users/u2/roles", `{"role_ids":["r-admin"]}`, owner); w.Code != 200 {
		t.Fatalf("make bob admin → %d", w.Code)
	}
	bw, _ = u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`)
	bob = sessionCookie(bw)
	w, out = u.call("POST", "/api/v1/admin/groups", `{"name":"Ops"}`, bob)
	if w.Code != 201 {
		t.Fatalf("admin creates → %d %v", w.Code, out)
	}
	ops := out["id"].(string)
	if w, out := u.call("PUT", "/api/v1/admin/groups/"+ops+"/roles", `{"role_ids":["r-auditor"]}`, bob); w.Code != 403 || out["reason"] != "self_escalation" {
		t.Fatalf("escalation → %d %v", w.Code, out)
	}
	aw.Flush()
	refused := 0
	for _, r := range u.ms.AuditRows {
		if r.EventType == string(audit.GroupRoleGranted) && r.Outcome == "refused" {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("refusal must be audited once: %d", refused)
	}
}

// TestInviteWithGroups (feature 004): the invitation body carries groups and
// names; acceptance joins the group and fills the profile.
func TestInviteWithGroups(t *testing.T) {
	u := newUS1(t)
	aw, _ := withGroups(t, u)
	defer aw.Close()
	ow, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	owner := sessionCookie(ow)
	_, g := u.call("POST", "/api/v1/admin/groups", `{"name":"Finance"}`, owner)
	gid := g["id"].(string)
	u.call("PUT", "/api/v1/admin/groups/"+gid+"/roles", `{"role_ids":["r-auditor"]}`, owner)
	if w, out := u.call("POST", "/api/v1/admin/invitations", `{"email":"new@x.test","group_ids":["`+gid+`"],"first_name":"New","last_name":"Person"}`, owner); w.Code != 202 {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/admin/invitations", `{"email":"x@x.test","group_ids":["0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c00"]}`, owner); w.Code != 400 {
		t.Fatalf("unknown group -> %d", w.Code)
	}
	p, _ := u.outbox.Decode("new@x.test", u.ms.Outbox[len(u.ms.Outbox)-1].PayloadEnc)
	tok := strings.TrimSpace(p.Text[strings.Index(p.Text, "token=")+6:])
	w, out := u.call("POST", "/api/v1/invitations/accept", `{"token":"`+tok+`","display_name":"","password":"a-long-enough-password"}`)
	if w.Code != 200 {
		t.Fatalf("%d %v", w.Code, out)
	}
	newbie := sessionCookie(w)
	w, out = u.call("GET", "/api/v1/session", "", newbie)
	if w.Code != 200 || out["user"].(map[string]any)["display_name"] != "New Person" || out["roles"].([]any)[0] != "auditor" {
		t.Fatalf("%d %v", w.Code, out)
	}
	w, out = u.call("GET", "/api/v1/admin/users/"+out["user"].(map[string]any)["id"].(string)+"/groups", "", owner)
	if w.Code != 200 || out["items"].([]any)[0].(map[string]any)["name"] != "Finance" {
		t.Fatalf("%d %v", w.Code, out)
	}
}
