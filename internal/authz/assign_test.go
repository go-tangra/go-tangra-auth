package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
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
