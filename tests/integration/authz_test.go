//go:build integration

package integration

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

func svcCtx() context.Context {
	return tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindService, ServiceID: "spiffe://example.org/svc/test"})
}

// TestAuthzDecisions: quickstart §7 — custom role allow/deny with reasons,
// deactivated user denied, unknown permission named.
func TestAuthzDecisions(t *testing.T) {
	e := Start(t)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	if _, err := e.App.Registry.Register(svcCtx(), tid, "billing", "spiffe://example.org/svc/test", []authz.Permission{{Resource: "invoices", Action: "read"}, {Resource: "invoices", Action: "write"}}); err != nil {
		t.Fatal(err)
	}
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	code, role := e.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": "reviewer", "display_name": "Reviewer", "permissions": []string{"billing:invoices:read"}})
	if code != 201 {
		t.Fatalf("%d %v", code, role)
	}
	_, carol := e.Seed("acme", "carol@acme.test", pw, "")
	if code, _ := e.JSON(http.MethodPut, "/api/v1/admin/users/"+carol+"/roles", map[string]any{"role_ids": []string{role["id"].(string)}}); code != 200 {
		t.Fatal(code)
	}
	read, write, nope := authz.PermissionRef{Module: "billing", Resource: "invoices", Action: "read"}, authz.PermissionRef{Module: "billing", Resource: "invoices", Action: "write"}, authz.PermissionRef{Resource: "x", Action: "y"}
	ds, err := e.App.Decider.BatchDecide(svcCtx(), tid, carol, []authz.PermissionRef{read, write, nope})
	if err != nil {
		t.Fatal(err)
	}
	if !ds[0].Allowed || ds[0].Reason != "role:reviewer" || ds[1].Allowed || ds[1].Reason != authz.ReasonNoPermission || ds[2].Reason != authz.ReasonUnknownPermission {
		t.Fatalf("%+v", ds)
	}
	if code, _ := e.JSON(http.MethodPost, "/api/v1/admin/users/"+carol+"/deactivate", nil); code != 204 {
		t.Fatal(code)
	}
	if d, _ := e.App.Decider.Decide(svcCtx(), tid, carol, read); d.Allowed || d.Reason != authz.ReasonUserInactive {
		t.Fatalf("%+v", d)
	}
}

// TestSelfEscalation: an admin cannot grant what they do not hold.
func TestSelfEscalation(t *testing.T) {
	e := Start(t)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	_, adm := e.Seed("acme", "admin@acme.test", pw, "")
	e.Bind(tid, adm, roles, "admin")
	_, _ = e.App.Registry.Register(svcCtx(), tid, "billing", "svc", []authz.Permission{{Resource: "invoices", Action: "write"}})
	b := e.Browser()
	if b.SignIn("acme", "admin@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	code, out := b.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": "billing", "display_name": "Billing", "permissions": []string{"billing:invoices:write"}})
	if code != 403 || out["reason"] != "self_escalation" {
		t.Fatalf("%d %v", code, out)
	}
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("owner sign-in")
	}
	if code, _ := e.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": "billing", "display_name": "Billing", "permissions": []string{"billing:invoices:write"}}); code != 201 {
		t.Fatalf("owner → %d", code)
	}
}

// TestPropagation: a role change is visible to decisions within 5 s.
func TestPropagation(t *testing.T) {
	e := Start(t)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	_, _ = e.App.Registry.Register(svcCtx(), tid, "billing", "svc", []authz.Permission{{Resource: "invoices", Action: "read"}})
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	_, role := e.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": "reviewer", "display_name": "Reviewer", "permissions": []string{"billing:invoices:read"}})
	_, carol := e.Seed("acme", "carol@acme.test", pw, "")
	read := authz.PermissionRef{Module: "billing", Resource: "invoices", Action: "read"}
	if d, _ := e.App.Decider.Decide(svcCtx(), tid, carol, read); d.Allowed {
		t.Fatal("not yet assigned")
	}
	start := time.Now()
	if code, _ := e.JSON(http.MethodPut, "/api/v1/admin/users/"+carol+"/roles", map[string]any{"role_ids": []string{role["id"].(string)}}); code != 200 {
		t.Fatal(code)
	}
	for {
		d, _ := e.App.Decider.Decide(svcCtx(), tid, carol, read)
		if d.Allowed {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("assignment not visible within 5 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code, _ := e.JSON(http.MethodPut, "/api/v1/admin/users/"+carol+"/roles", map[string]any{"role_ids": []string{}}); code != 200 {
		t.Fatal(code)
	}
	start = time.Now()
	for {
		d, _ := e.App.Decider.Decide(svcCtx(), tid, carol, read)
		if !d.Allowed {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("revocation not visible within 5 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestOpenFGAIdempotentWrites (feature 019, T007): with the write conflict
// options a duplicate add and a missing delete succeed against OpenFGA
// v1.20.0, and writes above the 100-tuple limit are chunked.
func TestOpenFGAIdempotentWrites(t *testing.T) {
	e := Start(t)
	tid, _ := e.Seed("acme", "owner@acme.test", pw, "")
	ctx := context.Background()
	p := authz.PermissionRef{Module: "warden", Resource: "backup", Action: "manage"}
	tuples := []authz.Tuple{authz.PermissionTenantTuple(tid, p), authz.RoleTenantTuple(tid, "m.warden.viewer"), authz.GrantTuple(tid, "m.warden.viewer", p)}
	for i := 0; i < 2; i++ {
		if err := e.App.FGA.Write(ctx, tuples, nil); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	missing := authz.GrantTuple(tid, "nobody", p)
	if err := e.App.FGA.Write(ctx, nil, []authz.Tuple{missing, missing}[:1]); err != nil {
		t.Fatalf("missing delete: %v", err)
	}
	var many []authz.Tuple
	for i := 0; i < 250; i++ {
		many = append(many, authz.PermissionTenantTuple(tid, authz.PermissionRef{Module: "bulk", Resource: "r" + strconv.Itoa(i), Action: "read"}))
	}
	if err := e.App.FGA.Write(ctx, many, nil); err != nil {
		t.Fatalf("250 tuples: %v", err)
	}
	if err := e.App.FGA.Write(ctx, many[:120], many[120:]); err != nil {
		t.Fatalf("mixed chunked write: %v", err)
	}
	ok, err := e.App.FGA.Check(ctx, authz.Tuple{User: authz.TenantObject(tid), Relation: "tenant", Object: authz.PermissionObject(tid, authz.PermissionRef{Module: "bulk", Resource: "r249", Action: "read"})})
	if err != nil || ok {
		t.Fatalf("deleted tuple still present: %v %v", ok, err)
	}
}
