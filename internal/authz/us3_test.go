package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

type us3 struct {
	ms   *memstore.Store
	fga  *Fake
	c    *Client
	reg  *Registry
	rl   *Roles
	dec  *Decider
	kv   *cache.Memory
	sys  context.Context
	own  context.Context
	adm  context.Context
	user context.Context
}

func newUS3(t *testing.T) *us3 {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddTenant(store.Tenant{ID: tB, Slug: "globex", Status: "suspended", Kind: "customer", Policy: []byte("{}")})
	ms.AddRole(store.Role{ID: "r-owner", TenantID: tA, Slug: "owner", Builtin: true})
	ms.AddRole(store.Role{ID: "r-admin", TenantID: tA, Slug: "admin", Builtin: true})
	ms.AddUser(store.User{ID: "u-owner", TenantID: tA, Email: "o@x", Status: "active"})
	ms.AddUser(store.User{ID: "u-admin", TenantID: tA, Email: "a@x", Status: "active"})
	ms.AddUser(store.User{ID: "u-bob", TenantID: tA, Email: "b@x", Status: "active"})
	ms.AddUser(store.User{ID: "u-gone", TenantID: tA, Email: "g@x", Status: "deactivated"})
	ms.AddUser(store.User{ID: "u-b", TenantID: tB, Email: "b@y", Status: "active"})
	_ = ms.ReplaceBindings(context.Background(), tA, "u-owner", "", []string{"r-owner"})
	_ = ms.ReplaceBindings(context.Background(), tA, "u-admin", "", []string{"r-admin"})
	kv := cache.NewMemory()
	fga := NewFake()
	c := New(fga, cache.New(kv), nil)
	h := &us3{ms: ms, fga: fga, c: c, kv: kv}
	h.reg = NewRegistry(ms, c, nil)
	h.rl = NewRoles(ms, c, NewEscalation(c), nil)
	h.dec = NewDecider(ms, c, nil)
	h.sys = tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindService, ServiceID: "spiffe://example.org/svc/billing"})
	h.own = tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", TenantID: tA, Roles: []string{"owner"}})
	h.adm = tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-admin", TenantID: tA, Roles: []string{"admin"}})
	h.user = tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-bob", TenantID: tA, Roles: nil})
	return h
}

func TestRegistry(t *testing.T) {
	h := newUS3(t)
	defs := []Permission{{"invoices", "read", "Read invoices"}, {"invoices", "write", "Write invoices"}}
	n, err := h.reg.Register(h.sys, tA, "spiffe://example.org/svc/billing", defs)
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if n, err := h.reg.Register(h.sys, tA, "spiffe://example.org/svc/billing", defs); err != nil || n != 2 {
		t.Fatal("idempotent", n, err)
	}
	list, _ := h.reg.List(context.Background(), tA)
	if len(list) != 2 || list[0].Description != "Read invoices" {
		t.Fatalf("%v", list)
	}
	if _, err := h.reg.Register(h.sys, tA, "svc", []Permission{{"Bad Res", "read", ""}}); !errors.Is(err, ErrBadPermission) {
		t.Fatal("malformed accepted")
	}
	if ok, _ := h.fga.Check(context.Background(), PermissionTenantTuple(tA, PermissionRef{"invoices", "read"})); !ok {
		t.Fatal("permission tenant tuple missing")
	}
	// A user of tenant A cannot register for tenant B.
	if _, err := h.reg.Register(h.user, tB, "x", defs); err == nil {
		t.Fatal("cross-tenant registration accepted")
	}
}

func TestRolesCRUDAndDecisions(t *testing.T) {
	h := newUS3(t)
	ctx := context.Background()
	_, _ = h.reg.Register(h.sys, tA, "svc", []Permission{{"invoices", "read", ""}, {"invoices", "write", ""}, {"audit", "read", ""}})
	// Built-ins are immutable; unknown permissions and bad slugs are refused.
	if _, err := h.rl.Update(h.own, tA, "r-admin", "Admins", []string{"invoices:read"}); !errors.Is(err, ErrBuiltin) {
		t.Fatalf("builtin update: %v", err)
	}
	if err := h.rl.Remove(h.own, tA, "r-owner"); !errors.Is(err, ErrBuiltin) {
		t.Fatalf("builtin remove: %v", err)
	}
	if _, err := h.rl.Create(h.own, tA, "auditor", "Auditor", []string{"nope:x"}); !errors.Is(err, ErrRoleRef) {
		t.Fatal("unknown permission accepted")
	}
	if _, err := h.rl.Create(h.own, tA, "Owner", "x", nil); !errors.Is(err, ErrRoleRef) {
		t.Fatal("bad slug accepted")
	}
	// Owner creates the auditor role; bob is assigned; decisions carry the role reason.
	auditor, err := h.rl.Create(h.own, tA, "auditor", "Auditor", []string{"audit:read", "invoices:read"})
	if err != nil || len(auditor.Permissions) != 2 {
		t.Fatal(auditor, err)
	}
	as := NewAssigner(h.ms, h.c, nil)
	if _, err := as.AssignRoles(h.own, tA, "u-bob", []string{auditor.ID}); err != nil {
		t.Fatal(err)
	}
	read, write, aread := PermissionRef{"invoices", "read"}, PermissionRef{"invoices", "write"}, PermissionRef{"audit", "read"}
	dec, err := h.dec.BatchDecide(h.sys, tA, "u-bob", []PermissionRef{read, write, aread, {"nope", "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !dec[0].Allowed || dec[0].Reason != "role:auditor" || dec[1].Allowed || dec[1].Reason != ReasonNoPermission || !dec[2].Allowed || dec[3].Reason != ReasonUnknownPermission {
		t.Fatalf("%+v", dec)
	}
	// Cached within the version; a role update bumps the version and changes the answer.
	if d, _ := h.dec.Decide(h.sys, tA, "u-bob", read); !d.Allowed {
		t.Fatal("cache hit")
	}
	if _, err := h.rl.Update(h.own, tA, auditor.ID, "", []string{"audit:read"}); err != nil {
		t.Fatal(err)
	}
	if d, _ := h.dec.Decide(h.sys, tA, "u-bob", read); d.Allowed {
		t.Fatal("stale decision after role update")
	}
	if d, _ := h.dec.Decide(h.sys, tA, "u-bob", aread); !d.Allowed {
		t.Fatal("kept permission")
	}
	// Status checks.
	if d, _ := h.dec.Decide(h.sys, tA, "u-gone", aread); d.Allowed || d.Reason != ReasonUserInactive {
		t.Fatalf("%+v", d)
	}
	if d, _ := h.dec.Decide(h.sys, tB, "u-b", aread); d.Allowed || d.Reason != ReasonTenantSuspended {
		t.Fatalf("%+v", d)
	}
	// Cross-tenant: a user of A asking about B is refused before FGA.
	if _, err := h.dec.Decide(h.user, tB, "u-b", aread); err == nil {
		t.Fatal("cross-tenant decision")
	}
	// Self-escalation: the admin (no explicit permissions) cannot create a role granting invoices:write.
	if _, err := h.rl.Create(h.adm, tA, "billing", "Billing", []string{"invoices:write"}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("escalation: %v", err)
	}
	// Give the admin invoices:write through a role and retry.
	billing, _ := h.rl.Create(h.own, tA, "billing", "Billing", []string{"invoices:write"})
	if _, err := as.AssignRoles(h.own, tA, "u-admin", []string{"r-admin", billing.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.rl.Create(h.adm, tA, "billing2", "Billing 2", []string{"invoices:write"}); err != nil {
		t.Fatalf("held permission: %v", err)
	}
	if _, err := h.rl.Update(h.adm, tA, billing.ID, "", []string{"invoices:write", "audit:read"}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatal("update escalation")
	}
	// Remove unassigns everyone and clears grants.
	if err := h.rl.Remove(h.own, tA, auditor.ID); err != nil {
		t.Fatal(err)
	}
	if roles, _ := h.ms.Roles(ctx, tA, "u-bob"); len(roles) != 0 {
		t.Fatalf("still assigned %v", roles)
	}
	if d, _ := h.dec.Decide(h.sys, tA, "u-bob", aread); d.Allowed {
		t.Fatal("removed role still grants")
	}
	list, _ := h.rl.List(h.own, tA)
	if len(list) != 4 { // owner, admin, billing, billing2
		t.Fatalf("%v", list)
	}
	if _, err := h.rl.List(h.user, tB); err == nil {
		t.Fatal("cross-tenant list")
	}
}
