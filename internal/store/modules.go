package store

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Feature 019: the platform module catalogue (system scope for writes,
// readable in every scope) and the per-tenant module state.

// UpsertModule records a module registration. An empty display name keeps
// the stored one (the name is used for a first registration without one);
// registering again un-retires a retired module.
func UpsertModule(ctx context.Context, tx pgx.Tx, name, displayName string) error {
	_, err := tx.Exec(ctx, `INSERT INTO modules (name, display_name) VALUES ($1, CASE WHEN $2 = '' THEN $1 ELSE $2 END)
		ON CONFLICT (name) DO UPDATE SET display_name = CASE WHEN $2 = '' THEN modules.display_name ELSE $2 END,
			updated_at = now(), retired_at = NULL`, name, displayName)
	return err
}

// ListModules returns every module of the catalogue by name.
func ListModules(ctx context.Context, tx pgx.Tx) ([]Module, error) {
	rows, err := tx.Query(ctx, "SELECT name, display_name, registered_at, updated_at, retired_at FROM modules ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Module
	for rows.Next() {
		var m Module
		if err := rows.Scan(&m.Name, &m.DisplayName, &m.RegisteredAt, &m.UpdatedAt, &m.RetiredAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RetireModule marks a module removed from the platform: its permissions and
// role definitions are retired with it.
func RetireModule(ctx context.Context, tx pgx.Tx, name string) error {
	ct, err := tx.Exec(ctx, "UPDATE modules SET retired_at = coalesce(retired_at, now()), updated_at = now() WHERE name = $1", name)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, "UPDATE module_permissions SET retired_at = coalesce(retired_at, now()) WHERE module = $1", name); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE module_role_defs SET retired_at = coalesce(retired_at, now()), updated_at = now() WHERE module = $1", name)
	return err
}

// UpsertModulePermission records a catalogue permission (un-retiring it).
func UpsertModulePermission(ctx context.Context, tx pgx.Tx, p ModulePermission) error {
	_, err := tx.Exec(ctx, `INSERT INTO module_permissions (module, resource, action, description) VALUES ($1,$2,$3,$4)
		ON CONFLICT (module, resource, action) DO UPDATE SET description = EXCLUDED.description, retired_at = NULL`,
		p.Module, p.Resource, p.Action, p.Description)
	return err
}

// ListModulePermissions returns the catalogue permissions of module, or of
// every module when module is empty.
func ListModulePermissions(ctx context.Context, tx pgx.Tx, module string) ([]ModulePermission, error) {
	rows, err := tx.Query(ctx, `SELECT module, resource, action, description, retired_at FROM module_permissions
		WHERE $1 = '' OR module = $1 ORDER BY module, resource, action`, module)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ModulePermission
	for rows.Next() {
		var p ModulePermission
		if err := rows.Scan(&p.Module, &p.Resource, &p.Action, &p.Description, &p.RetiredAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

const roleDefCols = "module, slug, display_name, description, permissions, updated_at, retired_at"

func scanRoleDef(r pgx.Row) (ModuleRoleDef, error) {
	var d ModuleRoleDef
	err := r.Scan(&d.Module, &d.Slug, &d.DisplayName, &d.Description, &d.Permissions, &d.UpdatedAt, &d.RetiredAt)
	return d, notFound(err)
}

// UpsertModuleRoleDef records a role definition (un-retiring it) and reports
// whether anything changed: new, different fields or permissions, or retired.
func UpsertModuleRoleDef(ctx context.Context, tx pgx.Tx, d ModuleRoleDef) (bool, error) {
	cur, err := scanRoleDef(tx.QueryRow(ctx, "SELECT "+roleDefCols+" FROM module_role_defs WHERE module = $1 AND slug = $2 FOR UPDATE", d.Module, d.Slug))
	switch {
	case err == nil:
		if cur.DisplayName == d.DisplayName && cur.Description == d.Description && slices.Equal(cur.Permissions, d.Permissions) && cur.RetiredAt == nil {
			return false, nil
		}
		_, err = tx.Exec(ctx, `UPDATE module_role_defs SET display_name = $3, description = $4, permissions = $5, retired_at = NULL, updated_at = now()
			WHERE module = $1 AND slug = $2`, d.Module, d.Slug, d.DisplayName, d.Description, d.Permissions)
		return err == nil, err
	case errors.Is(err, ErrNotFound):
		_, err = tx.Exec(ctx, "INSERT INTO module_role_defs (module, slug, display_name, description, permissions) VALUES ($1,$2,$3,$4,$5)",
			d.Module, d.Slug, d.DisplayName, d.Description, d.Permissions)
		return err == nil, err
	}
	return false, err
}

// ListModuleRoleDefs returns the role definitions of module, or of every
// module when module is empty, retired ones included.
func ListModuleRoleDefs(ctx context.Context, tx pgx.Tx, module string) ([]ModuleRoleDef, error) {
	rows, err := tx.Query(ctx, "SELECT "+roleDefCols+" FROM module_role_defs WHERE $1 = '' OR module = $1 ORDER BY module, slug", module)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ModuleRoleDef
	for rows.Next() {
		d, err := scanRoleDef(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RetireModuleRoleDef marks a definition no longer declared by its module.
func RetireModuleRoleDef(ctx context.Context, tx pgx.Tx, module, slug string) error {
	ct, err := tx.Exec(ctx, "UPDATE module_role_defs SET retired_at = coalesce(retired_at, now()), updated_at = now() WHERE module = $1 AND slug = $2", module, slug)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// GetTenantModule returns the module state of a tenant (ErrNotFound when the
// module never registered there).
func GetTenantModule(ctx context.Context, tx pgx.Tx, tenantID, module string) (TenantModule, error) {
	var m TenantModule
	err := tx.QueryRow(ctx, "SELECT tenant_id, module, first_registered_at, legacy_migrated_at FROM tenant_modules WHERE tenant_id = $1 AND module = $2", tenantID, module).
		Scan(&m.TenantID, &m.Module, &m.FirstRegisteredAt, &m.LegacyMigratedAt)
	return m, notFound(err)
}

// EnsureTenantModule records the first registration of a module in a tenant.
func EnsureTenantModule(ctx context.Context, tx pgx.Tx, tenantID, module string) error {
	_, err := tx.Exec(ctx, "INSERT INTO tenant_modules (tenant_id, module) VALUES ($1, $2) ON CONFLICT DO NOTHING", tenantID, module)
	return err
}

// MarkLegacyMigrated sets the access-preserving migration marker once.
func MarkLegacyMigrated(ctx context.Context, tx pgx.Tx, tenantID, module string, at time.Time) error {
	ct, err := tx.Exec(ctx, "UPDATE tenant_modules SET legacy_migrated_at = coalesce(legacy_migrated_at, $3) WHERE tenant_id = $1 AND module = $2", tenantID, module, at)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
