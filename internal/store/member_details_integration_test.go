//go:build integration

package store

import (
	"context"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestListMemberDetails: active members with login, display name, the same
// (role, source) rows EffectiveRoles returns and their group ids, under RLS,
// with the id filter, the login/display-name query and id paging.
func TestListMemberDetails(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tA, tB := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55", "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	dana, bob, eve, ivy, zed := "0190f7c2-6a3e-7c1a-9b2e-000000000001", "0190f7c2-6a3e-7c1a-9b2e-000000000002",
		"0190f7c2-6a3e-7c1a-9b2e-000000000003", "0190f7c2-6a3e-7c1a-9b2e-000000000004", "0190f7c2-6a3e-7c1a-9b2e-000000000009"
	rAdmin, rAccess, rWarden, rB := NewID(), NewID(), NewID(), NewID()
	gOps, gB := NewID(), NewID()
	if err := st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error {
		for i, id := range []string{tA, tB} {
			if err := InsertTenant(ctx, tx, Tenant{ID: id, Slug: "tenant-" + string(rune('a'+i)), DisplayName: "T", Status: "active", Kind: "customer", Policy: []byte("{}")}); err != nil {
				return err
			}
		}
		for _, u := range []User{
			{ID: dana, TenantID: tA, Email: "Dana@X.test", DisplayName: "Dana Kovač", Status: "active"},
			{ID: bob, TenantID: tA, Email: "bob@x.test", DisplayName: "Bob 100%_Stone", Status: "active"},
			{ID: eve, TenantID: tA, Email: "eve@x.test", DisplayName: "Eve", Status: "deactivated"},
			{ID: ivy, TenantID: tA, Email: "ivy@x.test", DisplayName: "Ivy", Status: "invited"},
			{ID: zed, TenantID: tB, Email: "dana@other.test", DisplayName: "Dana Foreign", Status: "active"},
		} {
			if err := InsertUser(ctx, tx, u); err != nil {
				return err
			}
		}
		for _, r := range []Role{
			{ID: rAdmin, TenantID: tA, Slug: "m.teleport.admin", DisplayName: "Admin", Origin: OriginModule, Module: "teleport", ModuleSlug: "admin"},
			{ID: rAccess, TenantID: tA, Slug: "m.teleport.access", DisplayName: "Access", Origin: OriginModule, Module: "teleport", ModuleSlug: "access"},
			{ID: rWarden, TenantID: tA, Slug: "m.warden.viewer", DisplayName: "Viewer", Origin: OriginModule, Module: "warden", ModuleSlug: "viewer"},
			{ID: rB, TenantID: tB, Slug: "m.teleport.admin", DisplayName: "Admin", Origin: OriginModule, Module: "teleport", ModuleSlug: "admin"},
		} {
			if err := InsertRole(ctx, tx, r); err != nil {
				return err
			}
		}
		if err := ReplaceRoleBindings(ctx, tx, tA, dana, "", []string{rAdmin, rWarden}); err != nil {
			return err
		}
		if err := ReplaceRoleBindings(ctx, tx, tA, eve, "", []string{rAdmin}); err != nil {
			return err
		}
		return ReplaceRoleBindings(ctx, tx, tB, zed, "", []string{rB})
	}); err != nil {
		t.Fatal(err)
	}
	in := func(tid string, fn func(tx pgx.Tx) error) {
		t.Helper()
		if err := st.Tx(ctx, Scope{TenantID: tid}, fn); err != nil {
			t.Fatal(err)
		}
	}
	in(tA, func(tx pgx.Tx) error {
		if err := InsertGroup(ctx, tx, Group{ID: gOps, TenantID: tA, Name: "Ops"}); err != nil {
			return err
		}
		if _, err := AddGroupMembers(ctx, tx, tA, gOps, "", []string{dana, bob, eve}); err != nil {
			return err
		}
		return ReplaceGroupRoles(ctx, tx, tA, gOps, "", []string{rAccess, rWarden})
	})
	in(tB, func(tx pgx.Tx) error {
		if err := InsertGroup(ctx, tx, Group{ID: gB, TenantID: tB, Name: "Ops"}); err != nil {
			return err
		}
		_, err := AddGroupMembers(ctx, tx, tB, gB, "", []string{zed})
		return err
	})
	list := func(tid string, f MemberFilter) (out []MemberDetail) {
		t.Helper()
		in(tid, func(tx pgx.Tx) (err error) { out, err = ListMemberDetails(ctx, tx, tid, f); return err })
		return out
	}
	idsOf := func(ms []MemberDetail) []string {
		var out []string
		for _, m := range ms {
			out = append(out, m.ID)
		}
		return out
	}
	all := list(tA, MemberFilter{Limit: 1000})
	if got := idsOf(all); !slices.Equal(got, []string{dana, bob}) {
		t.Fatalf("active members of A: %v", got)
	}
	d := all[0]
	if d.Login != "Dana@X.test" || d.DisplayName != "Dana Kovač" || !slices.Equal(d.GroupIDs, []string{gOps}) {
		t.Fatalf("dana %+v", d)
	}
	// The role rows are exactly what EffectiveRoles (the decision path's
	// mirror) returns for the same user.
	in(tA, func(tx pgx.Tx) error {
		for _, m := range all {
			rows, err := EffectiveRoles(ctx, tx, tA, m.ID)
			if err != nil {
				return err
			}
			if !slices.Equal(rows, m.Roles) {
				t.Fatalf("%s: member detail roles %+v, EffectiveRoles %+v", m.ID, m.Roles, rows)
			}
		}
		return nil
	})
	var slugs []string
	for _, r := range d.Roles {
		slugs = append(slugs, r.Slug+":"+r.Source)
	}
	if !slices.Equal(slugs, []string{"m.teleport.access:group", "m.teleport.admin:direct", "m.warden.viewer:direct", "m.warden.viewer:group"}) {
		t.Fatalf("dana rows %v", slugs)
	}
	// Tenant isolation: B sees only its member, A's ids through B yield nothing.
	if got := idsOf(list(tB, MemberFilter{Limit: 1000})); !slices.Equal(got, []string{zed}) {
		t.Fatalf("B %v", got)
	}
	if got := list(tB, MemberFilter{Limit: 1000, IDs: []string{dana, bob}}); len(got) != 0 {
		t.Fatalf("A ids via B %v", got)
	}
	if got := list(tA, MemberFilter{Limit: 1000, IDs: []string{zed}}); len(got) != 0 {
		t.Fatalf("B id via A %v", got)
	}
	// RLS: asking for B's rows inside A's scope returns nothing even if the
	// tenant argument were wrong.
	in(tA, func(tx pgx.Tx) error {
		out, err := ListMemberDetails(ctx, tx, tB, MemberFilter{Limit: 1000})
		if err != nil || len(out) != 0 {
			t.Fatalf("RLS leak %v %v", out, err)
		}
		return nil
	})
	// Filter: active ones among ids.
	if got := idsOf(list(tA, MemberFilter{Limit: 1000, IDs: []string{bob, eve, ivy}})); !slices.Equal(got, []string{bob}) {
		t.Fatalf("filter %v", got)
	}
	// Query: login or display name, case-insensitive, LIKE characters literal.
	for q, want := range map[string][]string{
		"dana": {dana}, "X.TEST": {dana, bob}, "Kovač": {dana}, "100%_": {bob}, "%": {bob}, "_": {bob}, "eve": nil, "foreign": nil,
	} {
		if got := idsOf(list(tA, MemberFilter{Limit: 1000, Query: q})); !slices.Equal(got, want) {
			t.Errorf("query %q: %v, want %v", q, got, want)
		}
	}
	// Paging by id.
	p1 := list(tA, MemberFilter{Limit: 1})
	p2 := list(tA, MemberFilter{Limit: 1, After: p1[0].ID})
	p3 := list(tA, MemberFilter{Limit: 1, After: p2[0].ID})
	if p1[0].ID != dana || p2[0].ID != bob || len(p3) != 0 {
		t.Fatalf("paging %v %v %v", idsOf(p1), idsOf(p2), idsOf(p3))
	}
}
