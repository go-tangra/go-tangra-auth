package authz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

type groupFixture struct {
	ms    *memstore.Store
	fga   *Fake
	c     *Client
	g     *Groups
	sys   context.Context
	owner context.Context
	mgr   context.Context
	read  PermissionRef
	write PermissionRef
}

func newGroupFixture(t *testing.T) *groupFixture {
	t.Helper()
	ctx := context.Background()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u-owner", TenantID: tA, Email: "owner@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "u-manager", TenantID: tA, Email: "manager@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "u-dana", TenantID: tA, Email: "dana@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "u-bob", TenantID: tA, Email: "bob@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "u-foreign", TenantID: tB, Email: "f@x.test", Status: "active"})
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
	_ = c.Write(sys, tA, []Tuple{RoleTenantTuple(tA, "auditor"), RoleTenantTuple(tA, "billing"), PermissionTenantTuple(tA, read), PermissionTenantTuple(tA, write),
		GrantTuple(tA, "auditor", read), GrantTuple(tA, "billing", write), RoleAssignmentTuple(tA, "auditor", "u-manager"), MembershipTuple(tA, "u-owner", "owner")}, nil)
	_ = ms.ReplaceBindings(ctx, tA, "u-owner", "", []string{"r-owner"})
	_ = ms.ReplaceBindings(ctx, tA, "u-manager", "", []string{"r-auditor"})
	w := audit.NewWriter(ms, nil)
	t.Cleanup(w.Close)
	return &groupFixture{ms: ms, fga: fga, c: c, g: NewGroups(ms, c, w), sys: sys, read: read, write: write,
		owner: tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", TenantID: tA, Roles: []string{"owner"}}),
		// An admin who is not an owner and, in OpenFGA, holds only audit:read.
		mgr: tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-manager", TenantID: tA, Roles: []string{"admin"}}),
	}
}

func (f *groupFixture) audited(t *testing.T, typ audit.EventType) int {
	t.Helper()
	f.g.audit.Flush()
	n := 0
	for _, r := range f.ms.AuditRows {
		if r.EventType == string(typ) && r.Outcome == "ok" {
			n++
		}
	}
	return n
}

func TestGroupLifecycleGrantsAndWithdrawsAccess(t *testing.T) {
	f := newGroupFixture(t)
	g, err := f.g.Create(f.owner, tA, "  Finance ", "Money people")
	if err != nil || g.Name != "Finance" || g.ID == "" {
		t.Fatalf("%+v %v", g, err)
	}
	if _, err := f.g.Create(f.owner, tA, "finance", ""); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("duplicate (case-insensitive) must be ErrNameTaken: %v", err)
	}
	for _, bad := range []string{"", strings.Repeat("x", 65), "bad\x00name", "   "} {
		if _, err := f.g.Create(f.owner, tA, bad, ""); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("%q must be ErrInvalidName: %v", bad, err)
		}
	}
	if _, err := f.g.SetRoles(f.owner, tA, g.ID, []string{"r-billing", "r-billing"}); err != nil {
		t.Fatal(err)
	}
	// Member gets the group's role on the next check; re-adding is a silent no-op.
	added, err := f.g.AddMembers(f.owner, tA, g.ID, []string{"u-dana", "u-dana"})
	if err != nil || added != 1 {
		t.Fatalf("added %d %v", added, err)
	}
	if ok, _ := f.c.Allowed(f.sys, tA, "u-dana", f.write); !ok {
		t.Fatal("group role must grant invoices:write to the member")
	}
	if added, err := f.g.AddMembers(f.owner, tA, g.ID, []string{"u-dana"}); err != nil || added != 0 {
		t.Fatalf("re-add: %d %v", added, err)
	}
	if n := f.audited(t, audit.GroupMemberAdded); n != 1 {
		t.Fatalf("one member_added event expected, got %d", n)
	}
	// Effective roles show the source.
	eff, err := f.g.EffectiveRoles(f.owner, tA, "u-dana")
	if err != nil || len(eff) != 1 || eff[0].Slug != "billing" || len(eff[0].Sources) != 1 || eff[0].Sources[0].Kind != "group" || eff[0].Sources[0].GroupName != "Finance" {
		t.Fatalf("effective %+v %v", eff, err)
	}
	// Removing the member withdraws access; removing again is idempotent.
	if err := f.g.RemoveMember(f.owner, tA, g.ID, "u-dana"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.c.Allowed(f.sys, tA, "u-dana", f.write); ok {
		t.Fatal("removed member must lose the grant")
	}
	if err := f.g.RemoveMember(f.owner, tA, g.ID, "u-dana"); err != nil {
		t.Fatal(err)
	}
	// Role revocation on the group withdraws access from every member.
	_, _ = f.g.AddMembers(f.owner, tA, g.ID, []string{"u-bob"})
	if _, err := f.g.SetRoles(f.owner, tA, g.ID, []string{"r-auditor"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.c.Allowed(f.sys, tA, "u-bob", f.write); ok {
		t.Fatal("role removed from the group must stop granting")
	}
	if ok, _ := f.c.Allowed(f.sys, tA, "u-bob", f.read); !ok {
		t.Fatal("new group role must grant")
	}
	if n := f.audited(t, audit.GroupRoleRevoked); n != 1 {
		t.Fatalf("role_revoked events %d", n)
	}
	// Direct + group: removing from the group keeps the direct grant.
	_ = f.ms.ReplaceBindings(context.Background(), tA, "u-bob", "", []string{"r-auditor"})
	_ = f.c.Write(f.sys, tA, []Tuple{RoleAssignmentTuple(tA, "auditor", "u-bob")}, nil)
	eff, _ = f.g.EffectiveRoles(f.owner, tA, "u-bob")
	if len(eff) != 1 || len(eff[0].Sources) != 2 {
		t.Fatalf("direct+group must fold into one role with two sources: %+v", eff)
	}
	_ = f.g.RemoveMember(f.owner, tA, g.ID, "u-bob")
	if ok, _ := f.c.Allowed(f.sys, tA, "u-bob", f.read); !ok {
		t.Fatal("direct grant must survive group removal")
	}
	// Rename and describe; delete needs the current member count.
	if _, err := f.g.Update(f.owner, tA, g.ID, "Finance & Ops", "d2"); err != nil {
		t.Fatal(err)
	}
	_, _ = f.g.AddMembers(f.owner, tA, g.ID, []string{"u-dana", "u-bob"})
	if err := f.g.Delete(f.owner, tA, g.ID, 1); !errors.Is(err, ErrMemberCountMismatch) {
		t.Fatalf("delete with a stale count: %v", err)
	}
	if err := f.g.Delete(f.owner, tA, g.ID, 2); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.c.Allowed(f.sys, tA, "u-dana", f.read); ok {
		t.Fatal("deleted group must withdraw access")
	}
	if _, err := f.g.Get(f.owner, tA, g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted group: %v", err)
	}
	if f.audited(t, audit.GroupCreated) != 1 || f.audited(t, audit.GroupUpdated) != 1 || f.audited(t, audit.GroupDeleted) != 1 {
		t.Fatal("lifecycle events must be audited once each")
	}
	list, _ := f.g.List(f.owner, tA, "")
	if len(list) != 0 {
		t.Fatalf("list after delete %+v", list)
	}
}

func TestGroupEscalationAndIsolation(t *testing.T) {
	f := newGroupFixture(t)
	g, _ := f.g.Create(f.owner, tA, "Finance", "")
	admins, _ := f.g.Create(f.owner, tA, "Admins", "")
	if _, err := f.g.SetRoles(f.owner, tA, admins.ID, []string{"r-admin"}); err != nil {
		t.Fatal(err)
	}
	// owner is never assignable through a group (the last-owner rule needs direct bindings).
	if _, err := f.g.SetRoles(f.owner, tA, admins.ID, []string{"r-owner"}); !errors.Is(err, ErrOwnerViaGroup) {
		t.Fatalf("owner via group: %v", err)
	}
	// An admin holding audit:read only cannot grant invoices:write or admin through a group.
	if _, err := f.g.SetRoles(f.mgr, tA, g.ID, []string{"r-billing"}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("escalation via group roles: %v", err)
	}
	if _, err := f.g.SetRoles(f.mgr, tA, g.ID, []string{"r-admin"}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("admin via group roles: %v", err)
	}
	if _, err := f.g.SetRoles(f.mgr, tA, g.ID, []string{"r-auditor"}); err != nil {
		t.Fatalf("held permission must be grantable: %v", err)
	}
	// ...nor add anyone (including themselves) to a group carrying admin or permissions they lack.
	_, _ = f.g.SetRoles(f.owner, tA, g.ID, []string{"r-billing"})
	if _, err := f.g.AddMembers(f.mgr, tA, g.ID, []string{"u-manager"}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("self-add to a privileged group: %v", err)
	}
	if _, err := f.g.AddMembers(f.mgr, tA, admins.ID, []string{"u-dana"}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("add to admins group: %v", err)
	}
	if n := f.audited(t, audit.GroupMemberAdded); n != 0 {
		t.Fatalf("refusals must not produce ok events: %d", n)
	}
	if f.ms.AuditRows[len(f.ms.AuditRows)-1].Outcome != "refused" {
		t.Fatal("refusal must be audited")
	}
	// Cross-tenant: foreign users, roles and groups are not found; the fake never sees a write.
	n := f.fga.Len()
	if _, err := f.g.AddMembers(f.owner, tA, g.ID, []string{"u-foreign"}); !errors.Is(err, store.ErrNotFound) || f.fga.Len() != n {
		t.Fatalf("foreign user: %v", err)
	}
	if _, err := f.g.SetRoles(f.owner, tA, g.ID, []string{"r-foreign"}); !errors.Is(err, store.ErrNotFound) || f.fga.Len() != n {
		t.Fatalf("foreign role: %v", err)
	}
	if _, err := f.g.Get(f.owner, tB, g.ID); !errors.Is(err, tenantctx.ErrCrossTenant) && !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign tenant: %v", err)
	}
	// A plain member (no actor roles) is refused by the guard before any read.
	member := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-dana", TenantID: tA, Roles: []string{"member"}})
	if _, err := f.g.Create(member, tA, "Mine", ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member creating a group: %v", err)
	}
	if _, err := f.g.AddMembers(member, tA, g.ID, []string{"u-dana"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member adding: %v", err)
	}
}
