package httpapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

func TestRoleHandlers(t *testing.T) {
	u := newUS1(t)
	aw, _ := withUS2(t, u)
	defer aw.Close()
	c := authz.New(authz.NewFake(), cache.New(cache.NewMemory()), nil)
	reg := authz.NewRegistry(u.ms, c, aw)
	u.srv.RegisterUS3(US3Deps{Roles: authz.NewRoles(u.ms, c, authz.NewEscalation(c), aw), Registry: reg})
	sys := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindSystem})
	if _, err := reg.Register(sys, tid, "svc", []authz.Permission{{Resource: "invoices", Action: "read", Description: "Read"}, {Resource: "invoices", Action: "write"}}); err != nil {
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
	w, out := u.call("POST", "/api/v1/admin/roles", `{"slug":"billing","display_name":"Billing","permissions":["invoices:read","invoices:write"]}`, owner)
	if w.Code != 201 || out["slug"] != "billing" || len(out["permissions"].([]any)) != 2 {
		t.Fatalf("%d %v", w.Code, out)
	}
	id := out["id"].(string)
	if w, out := u.call("POST", "/api/v1/admin/roles", `{"slug":"bad","display_name":"x","permissions":["nope:x"]}`, owner); w.Code != 400 || out["reason"] != "validation_failed" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("PUT", "/api/v1/admin/roles/r-admin", `{"display_name":"Admins","permissions":["invoices:read"]}`, owner); w.Code != 403 || out["reason"] != "builtin" {
		t.Fatalf("%d %v", w.Code, out)
	}
	if w, out := u.call("PUT", "/api/v1/admin/roles/"+id, `{"display_name":"Billing team","permissions":["invoices:read"]}`, owner); w.Code != 200 || out["display_name"] != "Billing team" || len(out["permissions"].([]any)) != 1 {
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
