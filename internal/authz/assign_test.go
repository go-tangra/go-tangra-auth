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

func TestAssignRoles(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	ms.AddRole(store.Role{ID: "r-owner", TenantID: tA, Slug: "owner", Builtin: true})
	ms.AddRole(store.Role{ID: "r-admin", TenantID: tA, Slug: "admin", Builtin: true})
	ms.AddRole(store.Role{ID: "r-auditor", TenantID: tA, Slug: "auditor"})
	ms.AddRole(store.Role{ID: "r-billing", TenantID: tA, Slug: "billing"})
	ms.AddRole(store.Role{ID: "r-foreign", TenantID: tB, Slug: "auditor"})
	ms.RolePerms["r-auditor"] = [][2]string{{"audit", "read"}}
	ms.RolePerms["r-billing"] = [][2]string{{"invoices", "write"}}
	fga := NewFake()
	c := New(fga, cache.New(cache.NewMemory()), nil)
	read, _ := ParsePermissionRef("audit:read")
	write, _ := ParsePermissionRef("invoices:write")
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	// Owner holds everything by design; the "auditor" role grants audit:read; "manager" holds audit:read only.
	_ = c.Write(sys, tA, []Tuple{RoleTenantTuple(tA, "auditor"), RoleTenantTuple(tA, "billing"), PermissionTenantTuple(tA, read), PermissionTenantTuple(tA, write),
		GrantTuple(tA, "auditor", read), GrantTuple(tA, "billing", write), RoleAssignmentTuple(tA, "auditor", "u-manager")}, nil)
	_ = ms.ReplaceBindings(ctx, tA, "u-owner", "", []string{"r-owner"})
	as := NewAssigner(ms, c, nil)

	owner := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", TenantID: tA, Roles: []string{"owner"}})
	slugs, err := as.AssignRoles(owner, tA, "u-bob", []string{"r-auditor", "r-billing", "r-billing"})
	if err != nil || len(slugs) != 2 {
		t.Fatalf("%v %v", slugs, err)
	}
	if ok, _ := c.Allowed(sys, tA, "u-bob", write); !ok {
		t.Fatal("tuple must grant the permission")
	}
	if roles, _ := ms.Roles(ctx, tA, "u-bob"); len(roles) != 2 {
		t.Fatalf("mirror rows %v", roles)
	}
	// Revoking removes tuples and mirror rows; the decision cache is invalidated.
	if _, err := as.AssignRoles(owner, tA, "u-bob", []string{"r-auditor"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Allowed(sys, tA, "u-bob", write); ok {
		t.Fatal("revoked role still grants")
	}
	// Self-escalation: a manager holding only audit:read cannot grant invoices:write, nor owner/admin.
	manager := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-manager", TenantID: tA, Roles: []string{"auditor"}})
	if _, err := as.AssignRoles(manager, tA, "u-carol", []string{"r-billing"}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("escalation: %v", err)
	}
	if _, err := as.AssignRoles(manager, tA, "u-carol", []string{"r-admin"}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("admin escalation: %v", err)
	}
	if _, err := as.AssignRoles(manager, tA, "u-carol", []string{"r-auditor"}); err != nil {
		t.Fatalf("held permission must be grantable: %v", err)
	}
	// Last owner keeps the owner role; a second owner may be demoted.
	if _, err := as.AssignRoles(owner, tA, "u-owner", []string{"r-auditor"}); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("last owner: %v", err)
	}
	if _, err := as.AssignRoles(owner, tA, "u-second", []string{"r-owner"}); err != nil {
		t.Fatal(err)
	}
	if _, err := as.AssignRoles(owner, tA, "u-owner", []string{"r-auditor"}); err != nil {
		t.Fatalf("demote with another owner: %v", err)
	}
	// Foreign role ids and foreign tenants are refused before any write.
	n := fga.Len()
	if _, err := as.AssignRoles(owner, tA, "u-bob", []string{"r-foreign"}); err == nil || fga.Len() != n {
		t.Fatal("foreign role accepted")
	}
	if _, err := as.AssignRoles(owner, tB, "u-bob", []string{"r-foreign"}); err == nil {
		t.Fatal("foreign tenant accepted")
	}
	if _, err := as.AssignRoles(ctx, tA, "u-bob", nil); !errors.Is(err, tenantctx.ErrNoActor) {
		t.Fatal("no actor")
	}
}

// MayAssign is the grant check shared by AssignRoles and invitations
// (activation and CreateWith): it only checks, never writes.
func TestMayAssign(t *testing.T) {
	f := newGroupFixture(t)
	ctx := context.Background()
	as := NewAssigner(f.ms, f.c, nil)
	owner := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", TenantID: tA, Roles: []string{"owner"}}
	// Non-owners whose OpenFGA permissions are audit:read only: a built-in admin and a custom-role holder.
	admin := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-manager", TenantID: tA, Roles: []string{"admin"}}
	custom := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-manager", TenantID: tA, Roles: []string{"auditor"}}
	// Callers (invite handlers) carry the actor in ctx, as AllowedMany requires.
	in := func(a tenantctx.Actor) context.Context { return tenantctx.WithActor(ctx, a) }
	n := f.fga.Len()

	// The owner may grant anything, including owner and admin.
	if err := as.MayAssign(in(owner), owner, tA, []string{"r-owner", "r-admin", "r-auditor", "r-billing"}); err != nil {
		t.Fatalf("owner: %v", err)
	}
	for _, actor := range []tenantctx.Actor{admin, custom} {
		for _, role := range []string{"r-owner", "r-admin", "r-billing"} {
			if err := as.MayAssign(in(actor), actor, tA, []string{role}); !errors.Is(err, ErrSelfEscalation) {
				t.Fatalf("%v granting %s: %v", actor.Roles, role, err)
			}
			// One escalating role refuses the whole set.
			if err := as.MayAssign(in(actor), actor, tA, []string{"r-auditor", role}); !errors.Is(err, ErrSelfEscalation) {
				t.Fatalf("%v granting auditor+%s: %v", actor.Roles, role, err)
			}
		}
		if err := as.MayAssign(in(actor), actor, tA, []string{"r-auditor", "r-auditor"}); err != nil {
			t.Fatalf("%v granting a held permission: %v", actor.Roles, err)
		}
		if err := as.MayAssign(in(actor), actor, tA, nil); err != nil {
			t.Fatalf("%v granting nothing: %v", actor.Roles, err)
		}
	}
	// Foreign role ids are not found, not an escalation; a foreign tenant is refused.
	if err := as.MayAssign(in(owner), owner, tA, []string{"r-foreign"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign role: %v", err)
	}
	if err := as.MayAssign(in(owner), owner, tB, []string{"r-foreign"}); err == nil {
		t.Fatal("foreign tenant accepted")
	}
	// A pure check: no tuples, no bindings.
	if f.fga.Len() != n {
		t.Fatal("MayAssign wrote tuples")
	}
	if roles, _ := f.ms.Roles(ctx, tA, "u-owner"); len(roles) != 1 {
		t.Fatalf("MayAssign touched bindings: %v", roles)
	}

	// Group-granted roles are checked through Escalation.MayGrant on the groups' permissions.
	esc := NewEscalation(f.c)
	finance, _ := f.g.Create(f.owner, tA, "Finance", "")
	readers, _ := f.g.Create(f.owner, tA, "Readers", "")
	if _, err := f.g.SetRoles(f.owner, tA, finance.ID, []string{"r-billing"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.g.SetRoles(f.owner, tA, readers.ID, []string{"r-auditor"}); err != nil {
		t.Fatal(err)
	}
	billing, _, err := f.g.groupGrants(ctx, tA, finance.ID)
	if err != nil || len(billing) == 0 {
		t.Fatalf("finance grants %v %v", billing, err)
	}
	reading, _, _ := f.g.groupGrants(ctx, tA, readers.ID)
	for _, actor := range []tenantctx.Actor{admin, custom} {
		if err := esc.MayGrant(in(actor), actor, tA, billing); !errors.Is(err, ErrSelfEscalation) {
			t.Fatalf("%v via group: %v", actor.Roles, err)
		}
		if err := esc.MayGrant(in(actor), actor, tA, reading); err != nil {
			t.Fatalf("%v via held group: %v", actor.Roles, err)
		}
	}
	if err := esc.MayGrant(in(owner), owner, tA, append(billing, reading...)); err != nil {
		t.Fatalf("owner via groups: %v", err)
	}
}

// AssignRoles keeps its behaviour after MayAssign is extracted: roles the
// target already holds are exempt from the grant check, new ones are not.
func TestAssignRolesUsesMayAssign(t *testing.T) {
	f := newGroupFixture(t)
	as := NewAssigner(f.ms, f.c, nil)
	if _, err := as.AssignRoles(f.owner, tA, "u-bob", []string{"r-billing"}); err != nil {
		t.Fatal(err)
	}
	custom := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-manager", TenantID: tA, Roles: []string{"auditor"}})
	if _, err := as.AssignRoles(custom, tA, "u-bob", []string{"r-billing", "r-auditor"}); err != nil {
		t.Fatalf("already-held role must not be re-checked: %v", err)
	}
	if _, err := as.AssignRoles(custom, tA, "u-dana", []string{"r-billing"}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("new role: %v", err)
	}
	if _, err := as.AssignRoles(f.mgr, tA, "u-dana", []string{"r-admin"}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("admin granting admin: %v", err)
	}
	if roles, _ := f.ms.Roles(context.Background(), tA, "u-dana"); len(roles) != 0 {
		t.Fatalf("refused assignment wrote bindings: %v", roles)
	}
}
