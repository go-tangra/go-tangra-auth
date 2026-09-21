package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/email"
	"github.com/go-freya/freya/services/auth/internal/invite"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/user"
)

type nullSender struct{}

func (nullSender) Send(context.Context, email.Message) error { return nil }

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
	u.srv.RegisterUS2(US2Deps{Invites: invite.New(u.ms, ob, az, aw, "https://auth.example.org"), Admin: user.NewAdmin(u.ms, sm, aw), Assigner: authz.NewAssigner(u.ms, az, aw), Audit: u.ms, Sessions: sm})
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
	tok := strings.TrimSpace(p.Text[strings.Index(p.Text, "token=")+6:])
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
