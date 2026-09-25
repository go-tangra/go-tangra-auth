package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
	"github.com/go-tangra/go-tangra-auth/v4/internal/invite"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/user"
)

type nullSender struct{}

func (nullSender) Deliver(context.Context, email.Message) (email.Outcome, error) {
	return email.Sent, nil
}

func withUS2(t *testing.T, u *us1) (*audit.Writer, *email.Outbox) {
	t.Helper()
	u.ms.AddRole(store.Role{ID: "r-owner", TenantID: tid, Slug: "owner", Builtin: true})
	u.ms.AddRole(store.Role{ID: "r-admin", TenantID: tid, Slug: "admin", Builtin: true})
	u.ms.AddRole(store.Role{ID: "r-auditor", TenantID: tid, Slug: "auditor"})
	_ = u.ms.ReplaceBindings(context.Background(), tid, "u1", "", []string{"r-owner"})
	h, _ := crypto.HashPassword("correct horse battery", crypto.DefaultParams)
	u.ms.AddUser(store.User{ID: "u2", TenantID: tid, Email: "bob@x.test", DisplayName: "Bob", Status: "active", PasswordHash: &h})
	_ = u.ms.ReplaceBindings(context.Background(), tid, "u2", "", nil)
	c := cache.New(cache.NewMemory())
	aw := audit.NewWriter(u.ms, nil)
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{8}, 32))
	ob := email.NewOutbox(env, nullSender{}, nil, 3, nil)
	az := authz.New(authz.NewFake(), c, nil)
	sm := u.sessions
	as := authz.NewAssigner(u.ms, az, aw)
	inv := invite.New(u.ms, ob, az, aw, "https://auth.example.org").WithEscalation(authz.InviteEscalation{Assigner: as, Groups: authz.NewGroups(u.ms, az, aw)})
	u.srv.RegisterUS2(US2Deps{Invites: inv, Admin: user.NewAdmin(u.ms, sm, aw), Assigner: as, Audit: u.ms, Sessions: sm})
	return aw, ob
}

func TestAdminHandlers(t *testing.T) {
	u := newUS1(t)
	aw, ob := withUS2(t, u)
	defer aw.Close()
	// Bob (no roles) is refused; the owner may administer.
	bw, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`)
	bob := sessionCookie(bw)
	if w, out := u.call("GET", "/api/v1/admin/users", "", bob); w.Code != 403 || out["reason"] != "forbidden" {
		t.Fatalf("%d %v", w.Code, out)
	}
	ow, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	owner := sessionCookie(ow)
	w, out := u.call("GET", "/api/v1/admin/users?q=bob", "", owner)
	items := out["items"].([]any)
	if w.Code != 200 || len(items) != 1 || items[0].(map[string]any)["email"] != "bob@x.test" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Invite: identical 202 for a new and an existing address; bad email 400.
	if w, out := u.call("POST", "/api/v1/admin/invitations", `{"email":"new@x.test","role_ids":["r-auditor"]}`, owner); w.Code != 202 || out["queued"] != true {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/admin/invitations", `{"email":"bob@x.test"}`, owner); w.Code != 202 || out["queued"] != true {
		t.Fatalf("existing address must look identical: %d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/admin/invitations", `{"email":"nope"}`, owner); w.Code != 400 {
		t.Fatalf("bad email → %d", w.Code)
	}
	var invID string
	for id := range u.ms.Invitations {
		invID = id
	}
	if w, _ := u.call("POST", "/api/v1/admin/invitations/"+invID+"/resend", "", owner); w.Code != 202 {
		t.Fatalf("resend → %d", w.Code)
	}
	if w, _ := u.call("POST", "/api/v1/admin/invitations/nope/resend", "", owner); w.Code != 404 {
		t.Fatal("unknown invitation")
	}
	// Accept the (latest) token: account active, signed in, auditor role.
	p, _ := ob.Decode("new@x.test", u.ms.Outbox[len(u.ms.Outbox)-1].PayloadEnc)
	tok := p.Link()[strings.Index(p.Link(), "token=")+6:]
	if w, out := u.call("POST", "/api/v1/invitations/accept", `{"token":"`+tok+`","display_name":"New","password":"short"}`); w.Code != 400 || out["reason"] != "password_policy" {
		t.Fatalf("%d %v", w.Code, out)
	}
	w, out = u.call("POST", "/api/v1/invitations/accept", `{"token":"`+tok+`","display_name":"New","password":"a-long-enough-password"}`)
	if w.Code != 200 || out["signed_in"] != true || sessionCookie(w) == nil {
		t.Fatalf("%d %v", w.Code, out)
	}
	newbie := sessionCookie(w)
	if w, out := u.call("GET", "/api/v1/session", "", newbie); w.Code != 200 || out["roles"].([]any)[0] != "auditor" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/invitations/accept", `{"token":"`+tok+`","display_name":"Again","password":"a-long-enough-password"}`); w.Code != 400 || out["reason"] != "invalid_token" {
		t.Fatalf("reuse → %d %v", w.Code, out)
	}
	// Roles: owner assigns admin to bob; bob then sees the admin listing.
	if w, out := u.call("PUT", "/api/v1/admin/users/u2/roles", `{"role_ids":["r-admin"]}`, owner); w.Code != 200 || out["roles"].([]any)[0] != "admin" {
		t.Fatalf("%d %v", w.Code, out)
	}
	bw, _ = u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`)
	bob = sessionCookie(bw)
	if w, _ := u.call("GET", "/api/v1/admin/users", "", bob); w.Code != 200 {
		t.Fatalf("admin bob → %d", w.Code)
	}
	if w, out := u.call("PUT", "/api/v1/admin/users/u1/roles", `{"role_ids":["r-auditor"]}`, owner); w.Code != 403 || out["reason"] != "last_owner" {
		t.Fatalf("last owner → %d %v", w.Code, out)
	}
	if w, out := u.call("PUT", "/api/v1/admin/users/u2/roles", `{"role_ids":["r-owner"]}`, bob); w.Code != 403 || out["reason"] != "self_escalation" {
		t.Fatalf("escalation → %d %v", w.Code, out)
	}
	if w, _ := u.call("PUT", "/api/v1/admin/users/0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99/roles", `{"role_ids":[]}`, owner); w.Code != 404 {
		t.Fatal("unknown user")
	}
	// Force sign-out, deactivate, reactivate.
	if w, _ := u.call("POST", "/api/v1/admin/users/u2/sessions/revoke", "", owner); w.Code != 204 {
		t.Fatal("force signout")
	}
	if w, _ := u.call("GET", "/api/v1/session", "", bob); w.Code != 401 {
		t.Fatal("bob still signed in")
	}
	if w, _ := u.call("POST", "/api/v1/admin/users/u2/deactivate", "", owner); w.Code != 204 {
		t.Fatal("deactivate")
	}
	if w, out := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`); w.Code != 401 || out["reason"] != "invalid_credentials" {
		t.Fatalf("deactivated sign-in → %d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/admin/users/u1/deactivate", "", owner); w.Code != 403 || out["reason"] != "last_owner" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, _ := u.call("POST", "/api/v1/admin/users/u2/reactivate", "", owner); w.Code != 204 {
		t.Fatal("reactivate")
	}
	// Audit trail: filtered, paged, tenant scoped; auditor may read it.
	aw.Close()
	w, _ = u.call("GET", "/api/v1/admin/audit?event_type=invite_created", "", owner)
	var page struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if w.Code != 200 || len(page.Items) < 2 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w, _ := u.call("GET", "/api/v1/admin/audit?event_type=made_up", "", owner); w.Code != 400 {
		t.Fatal("unknown event type")
	}
	if w, _ := u.call("GET", "/api/v1/admin/audit?from=yesterday", "", owner); w.Code != 400 {
		t.Fatal("bad time")
	}
	if w, _ := u.call("GET", "/api/v1/admin/audit", "", newbie); w.Code != 200 {
		t.Fatalf("auditor → %d", w.Code)
	}
}

// Feature 016: an imported user is only activated or removed; roles, status
// changes and group membership are refused (research D10).
func TestAdminRefusesImportedTarget(t *testing.T) {
	u := newUS1(t)
	aw, _ := withGroups(t, u)
	defer aw.Close()
	u.ms.AddUser(store.User{ID: "u5", TenantID: tid, Email: "imp@x.test", DisplayName: "Imp", Status: "imported"})
	ow, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	owner := sessionCookie(ow)

	if w, out := u.call("PUT", "/api/v1/admin/users/u5/roles", `{"role_ids":["r-auditor"]}`, owner); w.Code != 409 || out["reason"] != "invalid_state" {
		t.Fatalf("roles → %d %v", w.Code, out)
	}
	if roles, _ := u.ms.Roles(context.Background(), tid, "u5"); len(roles) != 0 {
		t.Fatalf("imported user got roles %v", roles)
	}
	for _, op := range []string{"deactivate", "reactivate"} {
		if w, out := u.call("POST", "/api/v1/admin/users/u5/"+op, "", owner); w.Code != 409 || out["reason"] != "invalid_state" {
			t.Fatalf("%s → %d %v", op, w.Code, out)
		}
	}
	if got, _ := u.ms.User(context.Background(), tid, "u5"); got.Status != "imported" {
		t.Fatalf("status changed to %q", got.Status)
	}
	// Group membership: the imported user is never added.
	w, out := u.call("POST", "/api/v1/admin/groups", `{"name":"Imported"}`, owner)
	if w.Code != 201 {
		t.Fatalf("create group → %d %v", w.Code, out)
	}
	gid, _ := out["id"].(string)
	if w, _ := u.call("POST", "/api/v1/admin/groups/"+gid+"/members", `{"user_ids":["u5"]}`, owner); w.Code == 200 {
		t.Fatal("imported user added to a group")
	}
	if n, _ := u.ms.CountGroupMembers(context.Background(), tid, gid); n != 0 {
		t.Fatalf("members = %d", n)
	}
	// An active user is unaffected.
	if w, out := u.call("PUT", "/api/v1/admin/users/u2/roles", `{"role_ids":["r-auditor"]}`, owner); w.Code != 200 {
		t.Fatalf("active roles → %d %v", w.Code, out)
	}
}
