//go:build integration

package store

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestMigrationGroupsProfiles covers 0005: new tables under RLS, new user and
// invitation columns, and the compatibility default for existing rows.
func TestMigrationGroupsProfiles(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	admin, _ := pgx.Connect(ctx, adminDSN)
	defer func() { _ = admin.Close(ctx) }()
	// Migrate up to 0004, seed a pre-feature user, then apply 0005.
	if err := MigrateTo(ctx, adminDSN, 4); err != nil {
		t.Fatal(err)
	}
	tid, uid := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55", "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	if _, err := admin.Exec(ctx, "INSERT INTO tenants (id, slug, display_name, status, kind, policy) VALUES ($1,'tenant-old','T','active','customer','{}')", tid); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "INSERT INTO users (id, tenant_id, email, display_name, status) VALUES ($1,$2,'old@x.test','Old Name','active')", uid, tid); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM pg_policies WHERE policyname = 'tenant_isolation' AND tablename IN ('groups','group_members','group_roles','avatars')").Scan(&n)
	if n != 4 {
		t.Fatalf("new tables under RLS: %d", n)
	}
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM pg_tables WHERE tablename IN ('groups','group_members','group_roles','avatars') AND rowsecurity").Scan(&n)
	if n != 4 {
		t.Fatalf("rowsecurity %d", n)
	}
	var first, phone, display string
	var explicit bool
	var avatar *string
	if err := admin.QueryRow(ctx, "SELECT first_name, phone, display_name, display_name_explicit, avatar_id FROM users WHERE id = $1", uid).Scan(&first, &phone, &display, &explicit, &avatar); err != nil {
		t.Fatal(err)
	}
	if first != "" || phone != "" || display != "Old Name" || !explicit || avatar != nil {
		t.Fatalf("existing row must keep its display name and start empty: %q %q %q %v %v", first, phone, display, explicit, avatar)
	}
	_ = admin.QueryRow(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'invitations' AND column_name IN ('group_ids','first_name','last_name')").Scan(&n)
	if n != 3 {
		t.Fatalf("invitation columns %d", n)
	}
	// The app role can use the new tables.
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Tx(ctx, Scope{TenantID: tid}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT 1 FROM groups LIMIT 1")
		return err
	}); err != nil {
		t.Fatalf("app role grant on groups: %v", err)
	}
}

// TestGroupRepos exercises groups, memberships, group roles, effective roles
// and avatars through the application role.
func TestGroupRepos(t *testing.T) {
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
	uA, uA2, uB := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77", "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c78", "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
	rAud, rInv := NewID(), NewID()
	if err := st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error {
		for i, id := range []string{tA, tB} {
			if err := InsertTenant(ctx, tx, Tenant{ID: id, Slug: "tenant-" + string(rune('a'+i)), DisplayName: "T", Status: "active", Kind: "customer", Policy: []byte("{}")}); err != nil {
				return err
			}
		}
		for _, u := range []User{{ID: uA, TenantID: tA, Email: "a@x.test", Status: "active"}, {ID: uA2, TenantID: tA, Email: "a2@x.test", Status: "active"}, {ID: uB, TenantID: tB, Email: "b@x.test", Status: "active"}} {
			if err := InsertUser(ctx, tx, u); err != nil {
				return err
			}
		}
		for _, r := range []Role{{ID: rAud, TenantID: tA, Slug: "auditor", DisplayName: "Auditor"}, {ID: rInv, TenantID: tA, Slug: "invoices-reader", DisplayName: "Invoices"}} {
			if err := InsertRole(ctx, tx, r); err != nil {
				return err
			}
		}
		return ReplaceRoleBindings(ctx, tx, tA, uA, "", []string{rAud})
	}); err != nil {
		t.Fatal(err)
	}
	gid := NewID()
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		return InsertGroup(ctx, tx, Group{ID: gid, TenantID: tA, Name: "Finance", Description: "d"})
	}); err != nil {
		t.Fatal(err)
	}
	// Unique per tenant, case-insensitive (its own transaction: the failed insert aborts it).
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		return InsertGroup(ctx, tx, Group{ID: NewID(), TenantID: tA, Name: "finance"})
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name must be ErrConflict, got %v", err)
	}
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		n, err := AddGroupMembers(ctx, tx, tA, gid, "", []string{uA, uA2})
		if err != nil || n != 2 {
			t.Fatalf("add members: %d %v", n, err)
		}
		n, err = AddGroupMembers(ctx, tx, tA, gid, "", []string{uA}) // idempotent
		if err != nil || n != 0 {
			t.Fatalf("re-add must be a no-op: %d %v", n, err)
		}
		if err := ReplaceGroupRoles(ctx, tx, tA, gid, "", []string{rInv, rAud}); err != nil {
			return err
		}
		rows, err := EffectiveRoles(ctx, tx, tA, uA)
		if err != nil {
			return err
		}
		// auditor: direct + group; invoices-reader: group.
		want := map[string]int{"auditor:direct": 0, "auditor:group": 0, "invoices-reader:group": 0}
		for _, r := range rows {
			key := r.Slug + ":" + r.Source
			if _, ok := want[key]; !ok {
				t.Fatalf("unexpected row %+v", r)
			}
			want[key]++
			if r.Source == "group" && (r.GroupID != gid || r.GroupName != "Finance") {
				t.Fatalf("group source must name the group: %+v", r)
			}
		}
		for k, c := range want {
			if c != 1 {
				t.Fatalf("row %s seen %d times", k, c)
			}
		}
		slugs, err := EffectiveRoleSlugs(ctx, tx, tA, uA)
		if err != nil || len(slugs) != 2 || slugs[0] != "auditor" || slugs[1] != "invoices-reader" {
			t.Fatalf("effective slugs must be distinct and sorted: %v %v", slugs, err)
		}
		groups, err := UserGroups(ctx, tx, tA, uA2)
		if err != nil || len(groups) != 1 || groups[0].Name != "Finance" {
			t.Fatalf("user groups %v %v", groups, err)
		}
		cnt, err := CountGroupMembers(ctx, tx, tA, gid)
		if err != nil || cnt != 2 {
			t.Fatalf("count %d %v", cnt, err)
		}
		if err := RemoveGroupMember(ctx, tx, tA, gid, uA2); err != nil {
			return err
		}
		if err := RemoveGroupMember(ctx, tx, tA, gid, uA2); err != nil { // idempotent
			return err
		}
		if err := ReplaceGroupRoles(ctx, tx, tA, gid, "", []string{rInv}); err != nil {
			return err
		}
		slugs, _ = EffectiveRoleSlugs(ctx, tx, tA, uA)
		if len(slugs) != 2 { // auditor direct, invoices via group
			t.Fatalf("after role replace %v", slugs)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Cross-tenant: tenant B sees nothing of tenant A's groups; adding B's user to A's group is refused.
	if err := st.Tx(ctx, Scope{TenantID: tB}, func(tx pgx.Tx) error {
		if _, err := GetGroup(ctx, tx, tA, gid); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-tenant group visible: %v", err)
		}
		gs, _ := ListGroups(ctx, tx, tB, "")
		if len(gs) != 0 {
			t.Fatalf("cross-tenant list %v", gs)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		_, err := AddGroupMembers(ctx, tx, tA, gid, "", []string{uB})
		return err
	}); err == nil {
		t.Fatal("member from another tenant must be refused")
	}
	// Research D10: an imported user is never added to a group (groups are
	// chosen at activation); the refusal looks like "not a user".
	uImp := NewID()
	if err := st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error {
		return InsertUser(ctx, tx, User{ID: uImp, TenantID: tA, Email: "imported@x.test", Status: "imported"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		_, err := AddGroupMembers(ctx, tx, tA, gid, "", []string{uImp})
		return err
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("imported member must be refused as ErrNotFound, got %v", err)
	}
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		groups, err := UserGroups(ctx, tx, tA, uImp)
		if err != nil {
			return err
		}
		if len(groups) != 0 {
			t.Fatalf("imported user became a member: %v", groups)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Role deletion cascades out of the group; group deletion cascades members.
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		if err := RemoveRole(ctx, tx, tA, rInv); err != nil {
			return err
		}
		slugs, _ := EffectiveRoleSlugs(ctx, tx, tA, uA)
		if len(slugs) != 1 || slugs[0] != "auditor" {
			t.Fatalf("role delete must withdraw group access: %v", slugs)
		}
		if err := DeleteGroup(ctx, tx, tA, gid); err != nil {
			return err
		}
		if _, err := GetGroup(ctx, tx, tA, gid); !errors.Is(err, ErrNotFound) {
			t.Fatalf("deleted group still visible: %v", err)
		}
		var n int
		_ = tx.QueryRow(ctx, "SELECT count(*) FROM group_members WHERE group_id = $1", gid).Scan(&n)
		if n != 0 {
			t.Fatalf("members not cascaded: %d", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Avatars: upsert replaces, delete clears the user's pointer, cross-tenant read is not found.
	if err := st.Tx(ctx, Scope{TenantID: tA}, func(tx pgx.Tx) error {
		if err := UpsertAvatar(ctx, tx, Avatar{ID: "a1", TenantID: tA, UserID: uA, ContentType: "image/jpeg", Bytes: []byte{1, 2, 3}}); err != nil {
			return err
		}
		if err := UpsertAvatar(ctx, tx, Avatar{ID: "a2", TenantID: tA, UserID: uA, ContentType: "image/jpeg", Bytes: []byte{4}}); err != nil {
			return err
		}
		if _, err := GetAvatar(ctx, tx, tA, uA, "a1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("replaced avatar must be gone: %v", err)
		}
		av, err := GetAvatar(ctx, tx, tA, uA, "a2")
		if err != nil || len(av.Bytes) != 1 {
			t.Fatalf("avatar %v %v", av, err)
		}
		u, _ := GetUser(ctx, tx, tA, uA)
		if u.AvatarID == nil || *u.AvatarID != "a2" {
			t.Fatalf("user avatar pointer %v", u.AvatarID)
		}
		if err := UpdateProfile(ctx, tx, tA, uA, ProfilePatch{FirstName: "Dana", LastName: "Kovač", Phone: "+385911234567", DisplayName: "Dana Kovač", DisplayNameExplicit: false}); err != nil {
			return err
		}
		u, _ = GetUser(ctx, tx, tA, uA)
		if u.FirstName != "Dana" || u.Phone != "+385911234567" || u.DisplayName != "Dana Kovač" || u.DisplayNameExplicit || u.ProfileUpdatedAt == nil {
			t.Fatalf("profile %+v", u)
		}
		found, err := ListUsers(ctx, tx, tA, "kova", "", 10)
		if err != nil || len(found) != 1 {
			t.Fatalf("search by last name %v %v", found, err)
		}
		pubs, err := LookupProfiles(ctx, tx, tA, []string{uA, uB, uA2})
		if err != nil || len(pubs) != 2 {
			t.Fatalf("lookup must omit foreign ids: %v %v", pubs, err)
		}
		if err := DeleteAvatar(ctx, tx, tA, uA); err != nil {
			return err
		}
		u, _ = GetUser(ctx, tx, tA, uA)
		if u.AvatarID != nil {
			t.Fatalf("avatar pointer not cleared")
		}
		return DeleteAvatar(ctx, tx, tA, uA) // idempotent
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Tx(ctx, Scope{TenantID: tB}, func(tx pgx.Tx) error {
		_, err := GetAvatar(ctx, tx, tA, uA, "a2")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-tenant avatar: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
