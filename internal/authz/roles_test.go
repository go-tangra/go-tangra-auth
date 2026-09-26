package authz

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// T040: module roles are locked (managed_role), every role but owner can be
// cloned into an editable custom role through the escalation check, legacy
// grants are not copied, and a taken slug is a conflict.
func TestLockAndClone(t *testing.T) {
	f := newModFixture(t)
	if _, err := f.mods.Register(f.sys, wardenReg(tA)); err != nil {
		t.Fatal(err)
	}
	viewer := f.roleBySlug(t, tA, "m.warden.viewer")
	if _, err := f.roles.Update(f.owner, tA, viewer.ID, "Mine", []string{"warden:secrets:write"}); !errors.Is(err, ErrManagedRole) {
		t.Fatalf("update module role: %v", err)
	}
	if err := f.roles.Remove(f.owner, tA, viewer.ID); !errors.Is(err, ErrManagedRole) {
		t.Fatalf("remove module role: %v", err)
	}
	if _, err := f.roles.Update(f.owner, tA, "r-admin-55", "x", nil); !errors.Is(err, ErrBuiltin) {
		t.Fatalf("update builtin: %v", err)
	}
	clone, err := f.roles.Clone(f.owner, tA, viewer.ID, "secret-readers", "Secret readers")
	if err != nil || clone.Origin != store.OriginCustom || clone.Locked || !slices.Equal(clone.Permissions, []string{"warden:secrets:read"}) {
		t.Fatalf("%+v %v", clone, err)
	}
	if _, err := f.roles.Update(f.owner, tA, clone.ID, "Secret team", []string{"warden:secrets:read", "warden:secrets:write"}); err != nil {
		t.Fatalf("clone not editable: %v", err)
	}
	// The source's legacy grants are not copied.
	c2, err := f.roles.Clone(f.owner, tA, "r-backups", "backups-2", "Backups 2")
	if err != nil || !slices.Equal(c2.Permissions, []string{"warden:backup:manage"}) {
		t.Fatalf("%+v %v", c2, err)
	}
	for _, p := range c2.Permissions {
		if p == "backup:manage" {
			t.Fatal("legacy grant copied")
		}
	}
	if ev := f.events(audit.RoleCloned); len(ev) != 2 || ev[0]["source"] != viewer.ID || ev[0]["slug"] != "secret-readers" {
		t.Fatalf("role_cloned %v", ev)
	}
	// Owner cannot be cloned; slugs are validated; a taken slug conflicts.
	if _, err := f.roles.Clone(f.owner, tA, "r-owner-55", "owners", "Owners"); !errors.Is(err, ErrBuiltin) {
		t.Fatalf("clone owner: %v", err)
	}
	if _, err := f.roles.Clone(f.owner, tA, viewer.ID, "secret-readers", "Again"); !errors.Is(err, ErrRoleConflict) {
		t.Fatalf("taken slug: %v", err)
	}
	for _, slug := range []string{"operator", "auditor", "m.warden.copy", "a.b", "Bad"} {
		if _, err := f.roles.Clone(f.owner, tA, viewer.ID, slug, "X"); !errors.Is(err, ErrRoleRef) {
			t.Fatalf("slug %q: %v", slug, err)
		}
	}
	if _, err := f.roles.Clone(f.owner, tA, "nope", "x-1", "X"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown source: %v", err)
	}
	// SR-003: an actor lacking a permission of the source is refused.
	bob := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-bob", TenantID: tA, Roles: []string{"admin"}})
	if _, err := f.roles.Clone(bob, tA, viewer.ID, "bobs-readers", "Bob"); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("escalation via clone: %v", err)
	}
	// Built-ins (not owner) are clonable templates.
	if _, err := f.roles.Clone(f.owner, tA, "r-admin-55", "admin-copy", "Admin copy"); err != nil {
		t.Fatalf("clone admin: %v", err)
	}
}

// T069 + reserved slugs: custom roles may not take a built-in slug or the
// module-role space; the list shows origins and module display names.
func TestCustomRoleSlugsAndViews(t *testing.T) {
	f := newModFixture(t)
	if _, err := f.mods.Register(f.sys, wardenReg(tA)); err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{"owner", "admin", "member", "auditor", "operator", "m.warden.viewer", "x.y"} {
		if _, err := f.roles.Create(f.owner, tA, slug, "X", nil); !errors.Is(err, ErrRoleRef) {
			t.Fatalf("reserved %q: %v", slug, err)
		}
	}
	if _, err := f.roles.Create(f.owner, tA, "backups", "Dup", nil); !errors.Is(err, ErrRoleConflict) {
		t.Fatalf("taken: %v", err)
	}
	// A legacy ref is never newly granted.
	if _, err := f.roles.Create(f.owner, tA, "legacy", "Legacy", []string{"backup:manage"}); !errors.Is(err, ErrRoleRef) {
		t.Fatalf("legacy grant: %v", err)
	}
	// ... but a custom role keeps the legacy grants it holds on update.
	if _, err := f.roles.Update(f.owner, tA, "r-backups", "", []string{"backup:manage", "warden:backup:manage"}); err != nil {
		t.Fatalf("keep legacy: %v", err)
	}
	if _, err := f.roles.Update(f.owner, tA, "r-readers", "", []string{"stats:read", "backup:manage"}); !errors.Is(err, ErrRoleRef) {
		t.Fatalf("add legacy: %v", err)
	}
	list, err := f.roles.List(f.owner, tA)
	if err != nil {
		t.Fatal(err)
	}
	byslug := map[string]RoleView{}
	for _, v := range list {
		byslug[v.Slug] = v
	}
	if v := byslug["m.warden.viewer"]; v.Origin != store.OriginModule || !v.Locked || v.ModuleDisplayName != "Warden" || v.ModuleSlug != "viewer" {
		t.Fatalf("%+v", v)
	}
	if v := byslug["admin"]; v.Origin != store.OriginBuiltin || !v.Locked {
		t.Fatalf("%+v", v)
	}
	if v := byslug["backups"]; v.Origin != store.OriginCustom || v.Locked {
		t.Fatalf("%+v", v)
	}
	names, err := f.roles.Names(context.Background(), tA)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n.Slug == "m.warden.viewer" && (n.ModuleDisplayName != "Warden" || n.Origin != store.OriginModule || n.Retired) {
			t.Fatalf("%+v", n)
		}
	}
}

// T041: assigning a module role passes the same escalation check as any
// role (users, groups, invitations); a retired role is refused unless held.
func TestModuleRoleAssignment(t *testing.T) {
	f := newModFixture(t)
	if _, err := f.mods.Register(f.sys, wardenReg(tA)); err != nil {
		t.Fatal(err)
	}
	viewer := f.roleBySlug(t, tA, "m.warden.viewer")
	as := NewAssigner(f.ms, f.c, f.aw)
	groups := NewGroups(f.ms, f.c, f.aw)
	// bob (admin, holds only backup permissions) may not hand out warden:secrets:read.
	bob := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-bob", TenantID: tA, Roles: []string{"admin"}})
	if _, err := as.AssignRoles(bob, tA, "u-erin", []string{viewer.ID}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("assign: %v", err)
	}
	grp, err := groups.Create(f.sys, tA, "Readers", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groups.SetRoles(bob, tA, grp.ID, []string{viewer.ID}); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("group: %v", err)
	}
	inv := InviteEscalation{Assigner: as, Groups: groups}
	if err := inv.MayAssign(bob, tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-bob", Roles: []string{"admin"}}, tA, []string{viewer.ID}, nil); !errors.Is(err, ErrSelfEscalation) {
		t.Fatalf("invite: %v", err)
	}
	// The owner assigns it to erin; then warden retires the viewer.
	if _, err := as.AssignRoles(f.owner, tA, "u-erin", []string{viewer.ID}); err != nil {
		t.Fatal(err)
	}
	reg := wardenReg(tA)
	reg.Roles = reg.Roles[:1]
	if _, err := f.mods.Register(f.sys, reg); err != nil {
		t.Fatal(err)
	}
	owner := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", Roles: []string{"owner"}}
	if _, err := as.AssignRoles(f.owner, tA, "u-carol", []string{viewer.ID}); !errors.Is(err, ErrRoleRetired) {
		t.Fatalf("retired to a new user: %v", err)
	}
	// Erin keeps it when her roles are saved again (not newly assigned).
	if _, err := as.AssignRoles(f.owner, tA, "u-erin", []string{viewer.ID}); err != nil {
		t.Fatalf("held retired role: %v", err)
	}
	if _, err := groups.SetRoles(f.owner, tA, grp.ID, []string{viewer.ID}); !errors.Is(err, ErrRoleRetired) {
		t.Fatalf("retired to a group: %v", err)
	}
	if err := inv.MayAssign(f.owner, owner, tA, []string{viewer.ID}, nil); !errors.Is(err, ErrRoleRetired) {
		t.Fatalf("retired in an invitation: %v", err)
	}
	op := tenantctx.WithOperatorGrant(context.Background(), "t", tA)
	opActor := tenantctx.Actor{Kind: tenantctx.KindOperator, UserID: "op"}
	if err := inv.MayAssign(tenantctx.WithActor(op, opActor), opActor, tA, []string{viewer.ID}, nil); !errors.Is(err, ErrRoleRetired) {
		t.Fatalf("retired by an operator: %v", err)
	}
	if ev := f.events(audit.RoleAssigned); len(ev) == 0 {
		t.Fatal("refusals not audited")
	}
}

// T071 (authz part): EnsureBuiltin adds missing built-in roles with their
// tenant tuple, adopts a custom role of the same slug and is idempotent.
func TestEnsureBuiltin(t *testing.T) {
	f := newModFixture(t)
	// tB has no auditor yet but a custom "auditor" role with a grant and an
	// assignment; tA lacks nothing.
	f.ms.AddRole(store.Role{ID: "r-aud-custom", TenantID: tB, Slug: "reviewer", DisplayName: "Reviewer"})
	roles, _ := f.ms.ListRoles(context.Background(), tB)
	for _, r := range roles {
		if r.Slug == "auditor" {
			_ = f.ms.RemoveRole(context.Background(), tB, r.ID) // builtin: refused by the store
		}
	}
	delete(f.ms.RoleRows, "r-auditor-66")
	f.ms.AddRole(store.Role{ID: "r-aud-old", TenantID: tB, Slug: "auditor", DisplayName: "Old auditors"})
	if changed, err := f.roles.EnsureBuiltin(f.sys, tB, []string{"owner", "admin", "member", "auditor", "operator"}); err != nil || !slices.Equal(changed, []string{"auditor", "operator"}) {
		t.Fatalf("%v %v", changed, err)
	}
	adopted, _ := f.ms.Role(context.Background(), tB, "r-aud-old")
	if !adopted.Builtin || adopted.OriginOf() != store.OriginBuiltin || adopted.DisplayName != "Old auditors" {
		t.Fatalf("%+v", adopted)
	}
	op := f.roleBySlug(t, tB, "operator")
	if !op.Builtin {
		t.Fatalf("%+v", op)
	}
	if ok, _ := f.fga.Check(context.Background(), RoleTenantTuple(tB, "operator")); !ok {
		t.Fatal("role tenant tuple missing")
	}
	if changed, err := f.roles.EnsureBuiltin(f.sys, tB, []string{"owner", "admin", "member", "auditor", "operator"}); err != nil || len(changed) != 0 {
		t.Fatalf("not idempotent: %v %v", changed, err)
	}
	f.aw.Flush()
	adoptedEvents := 0
	for _, r := range f.ms.AuditRows {
		if r.EventType == string(audit.RoleUpdated) && string(r.Details) != "" && strings.Contains(string(r.Details), `"adopted":true`) {
			adoptedEvents++
		}
	}
	if adoptedEvents != 1 {
		t.Fatalf("adopted events %d", adoptedEvents)
	}
	// Grants now reach the adopted auditor.
	if _, err := f.mods.Register(f.sys, wardenReg(tB)); err != nil {
		t.Fatal(err)
	}
	got, _ := f.ms.RolePermissions(context.Background(), tB, "r-aud-old")
	if !slices.Contains(refsOf(got), "warden:stats:read") {
		t.Fatalf("%v", refsOf(got))
	}
}
