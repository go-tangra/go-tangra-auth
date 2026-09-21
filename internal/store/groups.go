package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ---------------------------------------------------------------- groups

const groupCols = "id, tenant_id, name, description, created_by, created_at, updated_at"

func scanGroup(r pgx.Row) (Group, error) {
	var g Group
	err := r.Scan(&g.ID, &g.TenantID, &g.Name, &g.Description, &g.CreatedBy, &g.CreatedAt, &g.UpdatedAt)
	return g, notFound(err)
}

// conflict maps a unique-violation to ErrConflict.
func conflict(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrConflict
	}
	return err
}

// InsertGroup creates a group; a duplicate name (case-insensitive) is ErrConflict.
func InsertGroup(ctx context.Context, tx pgx.Tx, g Group) error {
	_, err := tx.Exec(ctx, "INSERT INTO groups (id, tenant_id, name, description, created_by) VALUES ($1,$2,$3,$4,NULLIF($5,'')::uuid)",
		g.ID, g.TenantID, g.Name, g.Description, deref(g.CreatedBy))
	return conflict(err)
}

// UpdateGroup renames/describes a group.
func UpdateGroup(ctx context.Context, tx pgx.Tx, tenantID, id, name, description string) error {
	ct, err := tx.Exec(ctx, "UPDATE groups SET name = $3, description = $4, updated_at = now() WHERE tenant_id = $1 AND id = $2", tenantID, id, name, description)
	if err != nil {
		return conflict(err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteGroup removes a group (members and roles cascade).
func DeleteGroup(ctx context.Context, tx pgx.Tx, tenantID, id string) error {
	ct, err := tx.Exec(ctx, "DELETE FROM groups WHERE tenant_id = $1 AND id = $2", tenantID, id)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// GetGroup by tenant + id.
func GetGroup(ctx context.Context, tx pgx.Tx, tenantID, id string) (Group, error) {
	return scanGroup(tx.QueryRow(ctx, "SELECT "+groupCols+" FROM groups WHERE tenant_id = $1 AND id = $2", tenantID, id))
}

// ListGroups of a tenant, optionally filtered by a name fragment.
func ListGroups(ctx context.Context, tx pgx.Tx, tenantID, q string) ([]Group, error) {
	rows, err := tx.Query(ctx, "SELECT "+groupCols+" FROM groups WHERE tenant_id = $1 AND ($2 = '' OR name ILIKE '%' || $2 || '%') ORDER BY lower(name), id", tenantID, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// CountGroupMembers of one group.
func CountGroupMembers(ctx context.Context, tx pgx.Tx, tenantID, groupID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, "SELECT count(*) FROM group_members WHERE tenant_id = $1 AND group_id = $2", tenantID, groupID).Scan(&n)
	return n, err
}

// GroupMemberCounts for a list of groups (list screens).
func GroupMemberCounts(ctx context.Context, tx pgx.Tx, tenantID string) (map[string]int, error) {
	rows, err := tx.Query(ctx, "SELECT group_id, count(*) FROM group_members WHERE tenant_id = $1 GROUP BY group_id", tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// ListGroupMembers pages members by (added_at, user_id) after cursor.
func ListGroupMembers(ctx context.Context, tx pgx.Tx, tenantID, groupID string, after time.Time, limit int) ([]GroupMember, error) {
	rows, err := tx.Query(ctx, `SELECT m.user_id, u.email, u.display_name, u.status, u.avatar_id, m.added_at
		FROM group_members m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND m.group_id = $2 AND m.added_at > $3 ORDER BY m.added_at, m.user_id LIMIT $4`, tenantID, groupID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.UserID, &m.Email, &m.DisplayName, &m.Status, &m.AvatarID, &m.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AddGroupMembers inserts memberships; existing ones are no-ops. Returns the
// number actually added. A user outside the tenant fails the RLS/FK checks.
func AddGroupMembers(ctx context.Context, tx pgx.Tx, tenantID, groupID, addedBy string, userIDs []string) (int, error) {
	added := 0
	for _, uid := range userIDs {
		ct, err := tx.Exec(ctx, `INSERT INTO group_members (group_id, user_id, tenant_id, added_by)
			SELECT $1, u.id, $3, NULLIF($4,'')::uuid FROM users u WHERE u.id = $2 AND u.tenant_id = $3
			ON CONFLICT DO NOTHING`, groupID, uid, tenantID, addedBy)
		if err != nil {
			return added, err
		}
		if ct.RowsAffected() == 0 {
			// Either already a member or not a user of this tenant.
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2)", groupID, uid).Scan(&exists); err != nil {
				return added, err
			}
			if !exists {
				return added, ErrNotFound
			}
			continue
		}
		added++
	}
	return added, nil
}

// RemoveGroupMember deletes a membership (idempotent).
func RemoveGroupMember(ctx context.Context, tx pgx.Tx, tenantID, groupID, userID string) error {
	_, err := tx.Exec(ctx, "DELETE FROM group_members WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3", tenantID, groupID, userID)
	return err
}

// IsGroupMember reports membership.
func IsGroupMember(ctx context.Context, tx pgx.Tx, tenantID, groupID, userID string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM group_members WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3)", tenantID, groupID, userID).Scan(&ok)
	return ok, err
}

// UserGroups lists the groups a user belongs to.
func UserGroups(ctx context.Context, tx pgx.Tx, tenantID, userID string) ([]Group, error) {
	rows, err := tx.Query(ctx, `SELECT g.id, g.tenant_id, g.name, g.description, g.created_by, g.created_at, g.updated_at
		FROM group_members m JOIN groups g ON g.id = m.group_id WHERE m.tenant_id = $1 AND m.user_id = $2 ORDER BY lower(g.name)`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ReplaceGroupRoles sets the group's roles.
func ReplaceGroupRoles(ctx context.Context, tx pgx.Tx, tenantID, groupID, grantedBy string, roleIDs []string) error {
	if _, err := tx.Exec(ctx, "DELETE FROM group_roles WHERE tenant_id = $1 AND group_id = $2", tenantID, groupID); err != nil {
		return err
	}
	for _, r := range roleIDs {
		if _, err := tx.Exec(ctx, "INSERT INTO group_roles (group_id, role_id, tenant_id, granted_by) VALUES ($1,$2,$3,NULLIF($4,'')::uuid)", groupID, r, tenantID, grantedBy); err != nil {
			return err
		}
	}
	return nil
}

// GroupRoles lists the roles of a group.
func GroupRoles(ctx context.Context, tx pgx.Tx, tenantID, groupID string) ([]Role, error) {
	rows, err := tx.Query(ctx, `SELECT r.id, r.tenant_id, r.slug, r.display_name, r.builtin, r.created_at, r.updated_at
		FROM group_roles gr JOIN roles r ON r.id = gr.role_id WHERE gr.tenant_id = $1 AND gr.group_id = $2 ORDER BY r.slug`, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GroupRoleSlugs maps every group of the tenant to its role slugs (list screens).
func GroupRoleSlugs(ctx context.Context, tx pgx.Tx, tenantID string) (map[string][]string, error) {
	rows, err := tx.Query(ctx, `SELECT gr.group_id, r.slug FROM group_roles gr JOIN roles r ON r.id = gr.role_id WHERE gr.tenant_id = $1 ORDER BY r.slug`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var g, s string
		if err := rows.Scan(&g, &s); err != nil {
			return nil, err
		}
		out[g] = append(out[g], s)
	}
	return out, rows.Err()
}

// EffectiveRoles returns every (role, source) pair of a user: direct bindings
// and roles inherited through group membership.
func EffectiveRoles(ctx context.Context, tx pgx.Tx, tenantID, userID string) ([]EffectiveRoleRow, error) {
	rows, err := tx.Query(ctx, `
		SELECT r.id, r.slug, 'direct', '', ''
		  FROM role_bindings b JOIN roles r ON r.id = b.role_id
		 WHERE b.tenant_id = $1 AND b.user_id = $2
		UNION ALL
		SELECT r.id, r.slug, 'group', g.id::text, g.name
		  FROM group_members m JOIN group_roles gr ON gr.group_id = m.group_id
		  JOIN roles r ON r.id = gr.role_id JOIN groups g ON g.id = m.group_id
		 WHERE m.tenant_id = $1 AND m.user_id = $2
		ORDER BY 2, 3, 5`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EffectiveRoleRow
	for rows.Next() {
		var r EffectiveRoleRow
		if err := rows.Scan(&r.RoleID, &r.Slug, &r.Source, &r.GroupID, &r.GroupName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EffectiveRoleSlugs is the distinct, sorted union of direct and group roles.
func EffectiveRoleSlugs(ctx context.Context, tx pgx.Tx, tenantID, userID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT slug FROM (
		  SELECT r.slug FROM role_bindings b JOIN roles r ON r.id = b.role_id WHERE b.tenant_id = $1 AND b.user_id = $2
		  UNION ALL
		  SELECT r.slug FROM group_members m JOIN group_roles gr ON gr.group_id = m.group_id JOIN roles r ON r.id = gr.role_id
		   WHERE m.tenant_id = $1 AND m.user_id = $2
		) s ORDER BY slug`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- profiles & avatars

// UpdateProfile writes the profile fields and the derived display name.
func UpdateProfile(ctx context.Context, tx pgx.Tx, tenantID, id string, p ProfilePatch) error {
	ct, err := tx.Exec(ctx, `UPDATE users SET first_name = $3, last_name = $4, phone = $5, display_name = $6, display_name_explicit = $7,
		profile_updated_at = now(), updated_at = now() WHERE tenant_id = $1 AND id = $2`,
		tenantID, id, p.FirstName, p.LastName, p.Phone, p.DisplayName, p.DisplayNameExplicit)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// UpsertAvatar stores the user's picture, replacing any previous one, and
// points the user at it.
func UpsertAvatar(ctx context.Context, tx pgx.Tx, a Avatar) error {
	if _, err := tx.Exec(ctx, "UPDATE users SET avatar_id = NULL WHERE tenant_id = $1 AND id = $2", a.TenantID, a.UserID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM avatars WHERE tenant_id = $1 AND user_id = $2", a.TenantID, a.UserID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO avatars (id, tenant_id, user_id, content_type, bytes, size) VALUES ($1,$2,$3,$4,$5,$6)",
		a.ID, a.TenantID, a.UserID, a.ContentType, a.Bytes, len(a.Bytes)); err != nil {
		return err
	}
	ct, err := tx.Exec(ctx, "UPDATE users SET avatar_id = $3, profile_updated_at = now(), updated_at = now() WHERE tenant_id = $1 AND id = $2", a.TenantID, a.UserID, a.ID)
	if err == nil && ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeleteAvatar removes the user's picture (idempotent).
func DeleteAvatar(ctx context.Context, tx pgx.Tx, tenantID, userID string) error {
	if _, err := tx.Exec(ctx, "UPDATE users SET avatar_id = NULL, profile_updated_at = now(), updated_at = now() WHERE tenant_id = $1 AND id = $2 AND avatar_id IS NOT NULL", tenantID, userID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "DELETE FROM avatars WHERE tenant_id = $1 AND user_id = $2", tenantID, userID)
	return err
}

// GetAvatar returns the bytes for (tenant, user, id); stale ids are not found.
func GetAvatar(ctx context.Context, tx pgx.Tx, tenantID, userID, id string) (Avatar, error) {
	var a Avatar
	err := tx.QueryRow(ctx, "SELECT id, tenant_id, user_id, content_type, bytes, created_at FROM avatars WHERE tenant_id = $1 AND user_id = $2 AND id = $3", tenantID, userID, id).
		Scan(&a.ID, &a.TenantID, &a.UserID, &a.ContentType, &a.Bytes, &a.CreatedAt)
	return a, notFound(err)
}

// SearchProfiles finds active members whose name or email contains q
// (case-insensitive), ordered by display name; at most limit rows.
func SearchProfiles(ctx context.Context, tx pgx.Tx, tenantID, q string, limit int) ([]PublicProfile, error) {
	rows, err := tx.Query(ctx, `SELECT id, display_name, avatar_id, email::text FROM users
		WHERE tenant_id = $1 AND status = 'active'
		AND (display_name ILIKE '%' || $2 || '%' OR first_name ILIKE '%' || $2 || '%' OR last_name ILIKE '%' || $2 || '%' OR email::text ILIKE '%' || $2 || '%')
		ORDER BY lower(display_name), id LIMIT $3`, tenantID, escapeLike(q), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublicProfile
	for rows.Next() {
		var p PublicProfile
		if err := rows.Scan(&p.ID, &p.DisplayName, &p.AvatarID, &p.Email); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// escapeLike neutralises LIKE metacharacters in user input.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// ListActiveMemberIDs pages the ids of active users of the tenant after
// the cursor id; with ids it returns the active ones among them.
func ListActiveMemberIDs(ctx context.Context, tx pgx.Tx, tenantID, after string, limit int, ids []string) ([]string, error) {
	var rows pgx.Rows
	var err error
	if len(ids) > 0 {
		rows, err = tx.Query(ctx, "SELECT id FROM users WHERE tenant_id = $1 AND status = 'active' AND id = ANY($2::uuid[]) ORDER BY id LIMIT $3", tenantID, ids, limit)
	} else {
		rows, err = tx.Query(ctx, "SELECT id FROM users WHERE tenant_id = $1 AND status = 'active' AND id::text > $2 ORDER BY id LIMIT $3", tenantID, after, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// LookupProfiles returns the public profile of the given users of the tenant;
// unknown or foreign ids are omitted.
func LookupProfiles(ctx context.Context, tx pgx.Tx, tenantID string, ids []string) ([]PublicProfile, error) {
	rows, err := tx.Query(ctx, "SELECT id, display_name, avatar_id FROM users WHERE tenant_id = $1 AND id = ANY($2::uuid[]) ORDER BY id", tenantID, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublicProfile
	for rows.Next() {
		var p PublicProfile
		if err := rows.Scan(&p.ID, &p.DisplayName, &p.AvatarID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
