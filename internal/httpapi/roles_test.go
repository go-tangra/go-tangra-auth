package httpapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

func TestRoleHandlers(t *testing.T) {
	u := newUS1(t)
	aw, _ := withUS2(t, u)
	defer aw.Close()
	c := authz.New(authz.NewFake(), cache.New(cache.NewMemory()), nil)
	reg := authz.NewRegistry(u.ms, c, aw)
	u.srv.RegisterUS3(US3Deps{Roles: authz.NewRoles(u.ms, c, authz.NewEscalation(c), aw), Registry: reg})
	sys := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindSystem})
	if _, err := reg.Register(sys, tid, "billing", "svc", []authz.Permission{{Resource: "invoices", Action: "read", Description: "Read"}, {Resource: "invoices", Action: "write"}}); err != nil {
		t.Fatal(err)
	}
	ow, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	owner := sessionCookie(ow)
	w, _ := u.call("GET", "/api/v1/admin/permissions", "", owner)
	var perms []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &perms)
	if w.Code != 200 || len(perms) != 2 || perms[0]["description"] != "Read" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w, out := u.call("POST", "/api/v1/admin/roles", `{"slug":"billing","display_name":"Billing","permissions":["billing:invoices:read","billing:invoices:write"]}`, owner)
	if w.Code != 201 || out["slug"] != "billing" || len(out["permissions"].([]any)) != 2 {
		t.Fatalf("%d %v", w.Code, out)
	}
	id := out["id"].(string)
	if w, out := u.call("POST", "/api/v1/admin/roles", `{"slug":"bad","display_name":"x","permissions":["billing:nope:x"]}`, owner); w.Code != 400 || out["reason"] != "validation_failed" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("PUT", "/api/v1/admin/roles/r-admin", `{"display_name":"Admins","permissions":["billing:invoices:read"]}`, owner); w.Code != 403 || out["reason"] != "builtin" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("PUT", "/api/v1/admin/roles/"+id, `{"display_name":"Billing team","permissions":["billing:invoices:read"]}`, owner); w.Code != 200 || out["display_name"] != "Billing team" || len(out["permissions"].([]any)) != 1 {
		t.Fatalf("%d %v", w.Code, out)
	}
	w, _ = u.call("GET", "/api/v1/admin/roles", "", owner)
	var roles []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &roles)
	if w.Code != 200 || len(roles) != 4 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w, _ := u.call("POST", "/api/v1/admin/roles/"+id+"/remove", "", owner); w.Code != 204 {
		t.Fatalf("remove → %d", w.Code)
	}
	if w, _ := u.call("POST", "/api/v1/admin/roles/"+id+"/remove", "", owner); w.Code != 404 {
		t.Fatal("removed twice")
	}
	// Non-admins are refused.
	bw, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`)
	if w, _ := u.call("GET", "/api/v1/admin/roles", "", sessionCookie(bw)); w.Code != 403 {
		t.Fatalf("bob → %d", w.Code)
	}
}

func TestListRoleNamesForMembers(t *testing.T) {
	u := newUS1(t)
	aw, _ := withUS2(t, u)
	defer aw.Close()
	c := authz.New(authz.NewFake(), cache.New(cache.NewMemory()), nil)
	u.srv.RegisterUS3(US3Deps{Roles: authz.NewRoles(u.ms, c, authz.NewEscalation(c), aw), Registry: authz.NewRegistry(u.ms, c, aw)})
	bw, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"bob@x.test","password":"correct horse battery"}`)
	bob := sessionCookie(bw)
	// Bob is a plain member: the admin list is refused, the name list is not.
	if w, _ := u.call("GET", "/api/v1/admin/roles", "", bob); w.Code != 403 {
		t.Fatalf("admin -> %d", w.Code)
	}
	w := u.raw("GET", "/api/v1/roles", nil, "", bob)
	var names []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &names)
	if w.Code != 200 || len(names) == 0 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, n := range names {
		if n["slug"] == "" || n["display_name"] == nil || n["permissions"] != nil || n["id"] != nil {
			t.Fatalf("shape: %v", n)
		}
	}
	if w, _ := u.call("GET", "/api/v1/roles", ""); w.Code != 401 {
		t.Fatalf("anonymous -> %d", w.Code)
	}
}

// Feature 019 (T040, T041, T049, T064): the catalogue carries modules and
// grantable; module roles are locked with a clone hint; clone creates a
// custom role; a retired role is refused for new assignments with 409.
func TestModuleRoleHandlers(t *testing.T) {
	u := newUS1(t)
	aw, _ := withUS2(t, u)
	defer aw.Close()
	c := authz.New(authz.NewFake(), cache.New(cache.NewMemory()), nil)
	reg := authz.NewRegistry(u.ms, c, aw)
	roles := authz.NewRoles(u.ms, c, authz.NewEscalation(c), aw)
	mods := authz.NewModules(u.ms, reg, roles, c, aw)
	u.srv.RegisterUS3(US3Deps{Roles: roles, Registry: reg})
	sys := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindSystem})
	warden := authz.Registration{Module: "warden", DisplayName: "Warden", Registrant: "spiffe://td/svc/warden", Tenants: []string{tid},
		Permissions: []authz.Permission{{Resource: "secrets", Action: "read"}, {Resource: "backup", Action: "manage"}},
		Roles:       []authz.ModuleRole{{Slug: "viewer", DisplayName: "Warden viewer", Description: "Read secrets", Permissions: []string{"secrets:read"}}}, DeclaresRoles: true}
	for _, r := range []authz.Registration{warden, {Module: "ipam", DisplayName: "IPAM", Registrant: "spiffe://td/svc/ipam", Tenants: []string{tid}, Permissions: []authz.Permission{{Resource: "backup", Action: "manage"}}}} {
		if _, err := mods.Register(sys, r); err != nil {
			t.Fatal(err)
		}
	}
	ow, _ := u.call("POST", "/api/v1/signin", `{"tenant":"acme","email":"alice@x.test","password":"correct horse battery"}`)
	owner := sessionCookie(ow)
	w, _ := u.call("GET", "/api/v1/admin/permissions", "", owner)
	var cat []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &cat)
	if w.Code != 200 || len(cat) != 3 || cat[0]["ref"] != "ipam:backup:manage" || cat[0]["module_display_name"] != "IPAM" || cat[1]["module"] != "warden" || cat[0]["grantable"] != true || cat[0]["legacy"] != false {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w, _ = u.call("GET", "/api/v1/admin/roles", "", owner)
	var list []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	var viewer map[string]any
	for _, r := range list {
		if r["slug"] == "m.warden.viewer" {
			viewer = r
		}
	}
	if viewer == nil || viewer["origin"] != "module" || viewer["locked"] != true || viewer["module_display_name"] != "Warden" || viewer["retired"] != false || viewer["description"] != "Read secrets" {
		t.Fatalf("%s", w.Body.String())
	}
	id := viewer["id"].(string)
	// Locked: update and remove refused with the clone hint.
	if w, out := u.call("PUT", "/api/v1/admin/roles/"+id, `{"display_name":"Mine","permissions":["warden:backup:manage"]}`, owner); w.Code != 403 || out["reason"] != "managed_role" || out["hint"] != "clone" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/admin/roles/"+id+"/remove", "", owner); w.Code != 403 || out["reason"] != "managed_role" {
		t.Fatalf("%d %v", w.Code, out)
	}
	// Clone.
	w, out := u.call("POST", "/api/v1/admin/roles/"+id+"/clone", `{"slug":"secret-readers","display_name":"Secret readers"}`, owner)
	if w.Code != 201 || out["origin"] != "custom" || out["locked"] != false || len(out["permissions"].([]any)) != 1 || out["permissions"].([]any)[0] != "warden:secrets:read" {
		t.Fatalf("%d %v", w.Code, out)
	}
	for body, want := range map[string]int{
		`{"slug":"secret-readers","display_name":"Again"}`: 409,
		`{"slug":"operator","display_name":"Op"}`:          400,
		`{"slug":"a.b","display_name":"Dot"}`:              400,
		`{"slug":"x-1"}`:                                   400,
	} {
		if w, out := u.call("POST", "/api/v1/admin/roles/"+id+"/clone", body, owner); w.Code != want {
			t.Fatalf("%s → %d %v", body, w.Code, out)
		}
	}
	if w, _ := u.call("POST", "/api/v1/admin/roles/r-owner/clone", `{"slug":"owners","display_name":"Owners"}`, owner); w.Code != 403 {
		t.Fatalf("clone owner → %d", w.Code)
	}
	if w, _ := u.call("POST", "/api/v1/admin/roles/0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99/clone", `{"slug":"ghost","display_name":"Ghost"}`, owner); w.Code != 404 {
		t.Fatalf("clone unknown → %d", w.Code)
	}
	// Reserved slugs on create.
	for _, slug := range []string{"auditor", "operator", "m.warden.x"} {
		if w, out := u.call("POST", "/api/v1/admin/roles", `{"slug":"`+slug+`","display_name":"X","permissions":[]}`, owner); w.Code != 400 || out["reason"] != "validation_failed" {
			t.Fatalf("%s → %d %v", slug, w.Code, out)
		}
	}
	// Retire the viewer: a new assignment is refused with 409 role_retired.
	warden.Roles = nil
	if _, err := mods.Register(sys, warden); err != nil {
		t.Fatal(err)
	}
	if w, out := u.call("PUT", "/api/v1/admin/users/u2/roles", `{"role_ids":["`+id+`"]}`, owner); w.Code != 409 || out["reason"] != "role_retired" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("POST", "/api/v1/admin/invitations", `{"email":"new@x.test","role_ids":["`+id+`"]}`, owner); w.Code != 409 || out["reason"] != "role_retired" {
		t.Fatalf("invite → %d %v", w.Code, out)
	}
	u.ms.AddUser(store.User{ID: "u-imp", TenantID: tid, Email: "imp@x.test", Status: "imported"})
	if w, out := u.call("POST", "/api/v1/admin/users/activate", `{"user_ids":["u-imp"],"role_ids":["`+id+`"]}`, owner); w.Code != 409 || out["reason"] != "role_retired" {
		t.Fatalf("activate → %d %v", w.Code, out)
	}
	w = u.raw("GET", "/api/v1/roles", nil, "", owner)
	var names []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &names)
	found := false
	for _, n := range names {
		if n["slug"] == "m.warden.viewer" {
			found = n["retired"] == true && n["origin"] == "module" && n["module_display_name"] == "Warden"
		}
	}
	if !found {
		t.Fatalf("%s", w.Body.String())
	}
}
