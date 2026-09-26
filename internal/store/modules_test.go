//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-auth/v4/internal/permref"
)

// TestMigration0011Upgrade (feature 019, T005): a database at 0010 with
// tenants, roles, grants and groups upgrades to 0011; existing rows become
// legacy permissions and built-in roles get origin builtin; the new CHECKs,
// RLS policies and grants are in force.
func TestMigration0011Upgrade(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := MigrateTo(ctx, adminDSN, 10); err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	// The auto-generated names 0011 replaces exist before the change.
	for tbl, name := range map[string]string{"permissions": "permissions_pkey", "role_permissions": "role_permissions_pkey", "roles": "roles_slug_check"} {
		var n int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_constraint WHERE conrelid = $1::regclass AND conname = $2", tbl, name).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s.%s before 0011: %d %v", tbl, name, n, err)
		}
	}
	tid, uid, gid := NewID(), NewID(), NewID()
	owner, custom := NewID(), NewID()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO tenants (id, slug, display_name, status, kind, policy) VALUES ($1,'acme','Acme','active','customer','{}')", []any{tid}},
		{"INSERT INTO users (id, tenant_id, email, display_name, status) VALUES ($1,$2,'a@x.test','A','active')", []any{uid, tid}},
		{"INSERT INTO roles (id, tenant_id, slug, display_name, builtin) VALUES ($1,$2,'owner','Owner',true)", []any{owner, tid}},
		{"INSERT INTO roles (id, tenant_id, slug, display_name, builtin) VALUES ($1,$2,'backups','Backups',false)", []any{custom, tid}},
		{"INSERT INTO permissions (tenant_id, resource, action, description, registered_by) VALUES ($1,'backup','manage','d','spiffe://td/svc/warden')", []any{tid}},
		{"INSERT INTO role_permissions (role_id, tenant_id, resource, action) VALUES ($1,$2,'backup','manage')", []any{custom, tid}},
		{"INSERT INTO role_bindings (user_id, role_id, tenant_id) VALUES ($1,$2,$3)", []any{uid, custom, tid}},
		{"INSERT INTO groups (id, tenant_id, name) VALUES ($1,$2,'ops')", []any{gid, tid}},
		{"INSERT INTO group_roles (group_id, role_id, tenant_id) VALUES ($1,$2,$3)", []any{gid, custom, tid}},
	} {
		if _, err := admin.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	inT := func(fn func(tx pgx.Tx) error) error { return st.Tx(ctx, Scope{TenantID: tid}, fn) }
	if err := inT(func(tx pgx.Tx) error {
		perms, err := ListPermissions(ctx, tx, tid)
		if err != nil || len(perms) != 1 || perms[0].Module != "" || perms[0].Ref().String() != "backup:manage" {
			t.Fatalf("legacy permission: %+v %v", perms, err)
		}
		grants, err := ListRolePermissions(ctx, tx, tid, custom)
		if err != nil || len(grants) != 1 || !grants[0].IsLegacy() {
			t.Fatalf("legacy grant: %+v %v", grants, err)
		}
		roles, err := ListRoles(ctx, tx, tid)
		if err != nil || len(roles) != 2 {
			t.Fatalf("roles %+v %v", roles, err)
		}
		for _, r := range roles {
			want := OriginCustom
			if r.Builtin {
				want = OriginBuiltin
			}
			if r.Origin != want || r.Module != "" || r.RetiredAt != nil {
				t.Fatalf("role %+v", r)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	exec := func(scope Scope, sql string, args ...any) error {
		return st.Tx(ctx, scope, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, sql, args...); return err })
	}
	// CHECKs: a custom slug with a dot, a module role without its module, a
	// builtin flag that disagrees with the origin, and a retired custom role.
	for name, q := range map[string]string{
		"custom dot":        "INSERT INTO roles (id, tenant_id, slug, display_name) VALUES ($1,$2,'m.warden.viewer','X')",
		"module no module":  "INSERT INTO roles (id, tenant_id, slug, display_name, origin) VALUES ($1,$2,'viewer','X','module')",
		"module wrong slug": "INSERT INTO roles (id, tenant_id, slug, display_name, origin, module, module_slug) VALUES ($1,$2,'m.ipam.viewer','X','module','warden','viewer')",
		"builtin mismatch":  "INSERT INTO roles (id, tenant_id, slug, display_name, builtin, origin) VALUES ($1,$2,'auditor','X',true,'custom')",
		"retired custom":    "INSERT INTO roles (id, tenant_id, slug, display_name, retired_at) VALUES ($1,$2,'old','X',now())",
		"bad module perm":   "INSERT INTO permissions (tenant_id, module, resource, action, registered_by) VALUES ($2,'Warden','x','y',$1::text)",
	} {
		if err := exec(Scope{TenantID: tid}, q, NewID(), tid); sqlState(err) != "23514" {
			t.Errorf("%s: %v, want check_violation", name, err)
		}
	}
	if err := inT(func(tx pgx.Tx) error {
		return InsertRole(ctx, tx, Role{ID: NewID(), TenantID: tid, Slug: "m.warden.viewer", DisplayName: "Warden viewer", Origin: OriginModule, Module: "warden", ModuleSlug: "viewer"})
	}); err != nil {
		t.Fatalf("module role: %v", err)
	}
	// Catalogue: readable in tenant scope, writable only with app.system.
	if err := exec(Scope{TenantID: tid}, "INSERT INTO modules (name, display_name) VALUES ('evil','Evil')"); err == nil {
		t.Fatal("tenant scope wrote the catalogue")
	}
	if err := st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error { return UpsertModule(ctx, tx, "warden", "Warden") }); err != nil {
		t.Fatal(err)
	}
	if err := inT(func(tx pgx.Tx) error {
		mods, err := ListModules(ctx, tx)
		if err != nil || len(mods) != 1 || mods[0].DisplayName != "Warden" {
			t.Fatalf("catalogue read in tenant scope: %+v %v", mods, err)
		}
		if _, err := tx.Exec(ctx, "UPDATE modules SET display_name = 'X'"); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var dn string
	_ = admin.QueryRow(ctx, "SELECT display_name FROM modules WHERE name = 'warden'").Scan(&dn)
	if dn != "Warden" {
		t.Fatalf("tenant scope updated the catalogue: %q", dn)
	}
	var canDelete bool
	_ = admin.QueryRow(ctx, "SELECT has_table_privilege('auth_app', 'modules', 'DELETE')").Scan(&canDelete)
	if canDelete {
		t.Fatal("auth_app may delete catalogue rows")
	}
	// tenant_modules is tenant-isolated.
	other := NewID()
	if err := exec(Scope{System: true}, "INSERT INTO tenants (id, slug, display_name, status, kind, policy) VALUES ($1,'other','O','active','customer','{}')", other); err != nil {
		t.Fatal(err)
	}
	if err := exec(Scope{TenantID: other}, "INSERT INTO tenant_modules (tenant_id, module) VALUES ($1,'warden')", tid); err == nil {
		t.Fatal("cross-tenant tenant_modules insert accepted")
	}
	if err := inT(func(tx pgx.Tx) error { return EnsureTenantModule(ctx, tx, tid, "warden") }); err != nil {
		t.Fatal(err)
	}
	if err := st.Tx(ctx, Scope{TenantID: other}, func(tx pgx.Tx) error {
		if _, err := GetTenantModule(ctx, tx, tid, "warden"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign tenant_modules row visible: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestModuleRepos (feature 019, T006): catalogue CRUD, retirement, the
// tenant marker, module-scoped permissions and role origins.
func TestModuleRepos(t *testing.T) {
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
	sys := func(fn func(tx pgx.Tx) error) error { return st.Tx(ctx, Scope{System: true}, fn) }
	tid := NewID()
	if err := sys(func(tx pgx.Tx) error {
		return InsertTenant(ctx, tx, Tenant{ID: tid, Slug: "mods", DisplayName: "T", Status: "active", Kind: "customer", Policy: []byte("{}")})
	}); err != nil {
		t.Fatal(err)
	}
	inT := func(fn func(tx pgx.Tx) error) error { return st.Tx(ctx, Scope{TenantID: tid}, fn) }

	t.Run("modules", func(t *testing.T) {
		if err := sys(func(tx pgx.Tx) error {
			if err := UpsertModule(ctx, tx, "ipam", ""); err != nil {
				return err
			}
			if err := UpsertModule(ctx, tx, "warden", "Warden"); err != nil {
				return err
			}
			return UpsertModule(ctx, tx, "warden", "") // keeps the display name
		}); err != nil {
			t.Fatal(err)
		}
		var mods []Module
		_ = inT(func(tx pgx.Tx) error { mods, err = ListModules(ctx, tx); return err })
		if len(mods) != 2 || mods[0].Name != "ipam" || mods[0].DisplayName != "ipam" || mods[1].DisplayName != "Warden" {
			t.Fatalf("%+v", mods)
		}
		if err := sys(func(tx pgx.Tx) error { return RetireModule(ctx, tx, "nope") }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("retire unknown: %v", err)
		}
	})

	t.Run("module permissions and role defs", func(t *testing.T) {
		if err := sys(func(tx pgx.Tx) error {
			for _, p := range []ModulePermission{{Module: "warden", Resource: "secrets", Action: "read"}, {Module: "warden", Resource: "backup", Action: "manage", Description: "b"}, {Module: "ipam", Resource: "backup", Action: "manage"}} {
				if err := UpsertModulePermission(ctx, tx, p); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		var all, warden []ModulePermission
		_ = inT(func(tx pgx.Tx) error {
			all, _ = ListModulePermissions(ctx, tx, "")
			warden, err = ListModulePermissions(ctx, tx, "warden")
			return err
		})
		if len(all) != 3 || len(warden) != 2 || warden[0].Resource != "backup" {
			t.Fatalf("%+v %+v", all, warden)
		}
		def := ModuleRoleDef{Module: "warden", Slug: "viewer", DisplayName: "Warden viewer", Permissions: []string{"secrets:read"}}
		var changed []bool
		if err := sys(func(tx pgx.Tx) error {
			for _, d := range []ModuleRoleDef{def, def, {Module: "warden", Slug: "viewer", DisplayName: "Warden viewer", Permissions: []string{"secrets:read", "backup:manage"}}} {
				c, err := UpsertModuleRoleDef(ctx, tx, d)
				if err != nil {
					return err
				}
				changed = append(changed, c)
			}
			return RetireModuleRoleDef(ctx, tx, "warden", "viewer")
		}); err != nil {
			t.Fatal(err)
		}
		if !changed[0] || changed[1] || !changed[2] {
			t.Fatalf("changed %v", changed)
		}
		var defs []ModuleRoleDef
		_ = inT(func(tx pgx.Tx) error { defs, err = ListModuleRoleDefs(ctx, tx, "warden"); return err })
		if len(defs) != 1 || defs[0].RetiredAt == nil || len(defs[0].Permissions) != 2 {
			t.Fatalf("%+v", defs)
		}
		// Declaring the same definition again un-retires it (a change).
		if err := sys(func(tx pgx.Tx) error {
			c, err := UpsertModuleRoleDef(ctx, tx, ModuleRoleDef{Module: "warden", Slug: "viewer", DisplayName: "Warden viewer", Permissions: []string{"secrets:read", "backup:manage"}})
			if err == nil && !c {
				t.Error("un-retire not reported as a change")
			}
			if err := RetireModuleRoleDef(ctx, tx, "warden", "absent"); !errors.Is(err, ErrNotFound) {
				t.Errorf("retire absent: %v", err)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		_ = inT(func(tx pgx.Tx) error { defs, err = ListModuleRoleDefs(ctx, tx, ""); return err })
		if len(defs) != 1 || defs[0].RetiredAt != nil {
			t.Fatalf("%+v", defs)
		}
		// Retiring the module retires its permissions and definitions.
		if err := sys(func(tx pgx.Tx) error { return RetireModule(ctx, tx, "warden") }); err != nil {
			t.Fatal(err)
		}
		_ = inT(func(tx pgx.Tx) error {
			defs, _ = ListModuleRoleDefs(ctx, tx, "warden")
			warden, err = ListModulePermissions(ctx, tx, "warden")
			return err
		})
		if defs[0].RetiredAt == nil || warden[0].RetiredAt == nil || warden[1].RetiredAt == nil {
			t.Fatalf("module retirement: %+v %+v", defs, warden)
		}
		// A new registration brings the module back.
		if err := sys(func(tx pgx.Tx) error { return UpsertModule(ctx, tx, "warden", "Warden") }); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("tenant marker", func(t *testing.T) {
		if err := inT(func(tx pgx.Tx) error {
			if _, err := GetTenantModule(ctx, tx, tid, "warden"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("before: %v", err)
			}
			if err := MarkLegacyMigrated(ctx, tx, tid, "warden", time.Now()); !errors.Is(err, ErrNotFound) {
				t.Fatalf("mark without row: %v", err)
			}
			for i := 0; i < 2; i++ {
				if err := EnsureTenantModule(ctx, tx, tid, "warden"); err != nil {
					return err
				}
			}
			m, err := GetTenantModule(ctx, tx, tid, "warden")
			if err != nil || m.LegacyMigratedAt != nil {
				t.Fatalf("%+v %v", m, err)
			}
			at := time.Now().Add(-time.Hour).Truncate(time.Second)
			if err := MarkLegacyMigrated(ctx, tx, tid, "warden", at); err != nil {
				return err
			}
			if err := MarkLegacyMigrated(ctx, tx, tid, "warden", time.Now()); err != nil { // kept once set
				return err
			}
			m, _ = GetTenantModule(ctx, tx, tid, "warden")
			if m.LegacyMigratedAt == nil || !m.LegacyMigratedAt.Equal(at) {
				t.Fatalf("marker %+v", m)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("scoped permissions and role origins", func(t *testing.T) {
		role := Role{ID: NewID(), TenantID: tid, Slug: "m.warden.viewer", DisplayName: "Warden viewer", Origin: OriginModule, Module: "warden", ModuleSlug: "viewer", Description: "Read"}
		custom := Role{ID: NewID(), TenantID: tid, Slug: "backups", DisplayName: "Backups"}
		if err := inT(func(tx pgx.Tx) error {
			for _, p := range []Permission{{Module: "warden", Resource: "backup", Action: "manage"}, {Module: "ipam", Resource: "backup", Action: "manage"}, {Resource: "backup", Action: "manage"}} {
				if err := UpsertPermission(ctx, tx, tid, p, "spiffe://td/svc/x"); err != nil {
					return err
				}
			}
			if err := UpsertPermission(ctx, tx, tid, Permission{Module: "warden", Resource: "backup", Action: "manage", Description: "new"}, "x"); err != nil {
				return err
			}
			if err := InsertRole(ctx, tx, role); err != nil {
				return err
			}
			if err := InsertRole(ctx, tx, custom); err != nil {
				return err
			}
			refs := []permref.Ref{{Module: "warden", Resource: "backup", Action: "manage"}, {Module: "ipam", Resource: "backup", Action: "manage"}, {Resource: "backup", Action: "manage"}}
			return ReplaceRolePermissions(ctx, tx, tid, custom.ID, append(refs, refs[0]))
		}); err != nil {
			t.Fatal(err)
		}
		if err := inT(func(tx pgx.Tx) error {
			return InsertRole(ctx, tx, Role{ID: NewID(), TenantID: tid, Slug: "backups", DisplayName: "Dup"})
		}); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate slug: %v", err)
		}
		if err := inT(func(tx pgx.Tx) error {
			perms, err := ListPermissions(ctx, tx, tid)
			if err != nil || len(perms) != 3 || perms[0].Module != "" || perms[2].Module != "warden" || perms[2].Description != "new" {
				t.Fatalf("%+v %v", perms, err)
			}
			grants, err := ListRolePermissions(ctx, tx, tid, custom.ID)
			if err != nil || len(grants) != 3 || grants[0].String() != "backup:manage" || grants[1].String() != "ipam:backup:manage" {
				t.Fatalf("%+v %v", grants, err)
			}
			got, err := GetRole(ctx, tx, tid, role.ID)
			if err != nil || got.Origin != OriginModule || got.Module != "warden" || got.ModuleSlug != "viewer" || got.Description != "Read" {
				t.Fatalf("%+v %v", got, err)
			}
			now := time.Now()
			if err := UpdateModuleRole(ctx, tx, tid, role.ID, "Warden reader", "R", &now); err != nil {
				return err
			}
			if err := UpdateModuleRole(ctx, tx, tid, custom.ID, "x", "", nil); !errors.Is(err, ErrNotFound) {
				t.Fatalf("module update of a custom role: %v", err)
			}
			got, _ = GetRole(ctx, tx, tid, role.ID)
			if got.DisplayName != "Warden reader" || got.RetiredAt == nil {
				t.Fatalf("%+v", got)
			}
			// Custom-only operations leave module roles alone.
			if err := UpdateRoleName(ctx, tx, tid, role.ID, "hijack"); err != nil {
				return err
			}
			if err := RemoveRole(ctx, tx, tid, role.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("remove module role: %v", err)
			}
			if err := AdoptBuiltinRole(ctx, tx, tid, role.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("adopt module role: %v", err)
			}
			if err := AdoptBuiltinRole(ctx, tx, tid, custom.ID); err != nil {
				return err
			}
			got, _ = GetRole(ctx, tx, tid, custom.ID)
			if !got.Builtin || got.Origin != OriginBuiltin {
				t.Fatalf("adopted %+v", got)
			}
			n, err := DeleteLegacyPermissions(ctx, tx, tid)
			if err != nil || n != 1 {
				t.Fatalf("prune %d %v", n, err)
			}
			grants, _ = ListRolePermissions(ctx, tx, tid, custom.ID)
			if len(grants) != 2 || grants[0].IsLegacy() {
				t.Fatalf("after prune %+v", grants)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
