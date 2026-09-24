// Package authzdb binds the authz package to the database. SQL bindings are
// kept apart from the security logic so the logic is unit-tested without a
// database; these bindings are covered by the tagged integration suite.
package authzdb

import (
	"context"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/jackc/pgx/v5"
)

// DBRoleStore is the database RoleStore (tenant scoped).
type DBRoleStore struct{ St *store.Store }

func (d DBRoleStore) RolesByID(ctx context.Context, tid string, ids []string) (out []store.Role, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		for _, id := range ids {
			r, err := store.GetRole(ctx, tx, tid, id)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	return
}
func (d DBRoleStore) UserRoles(ctx context.Context, tid, uid string) (out []store.Role, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		slugs, err := store.UserRoleSlugs(ctx, tx, tid, uid)
		if err != nil {
			return err
		}
		all, err := store.ListRoles(ctx, tx, tid)
		if err != nil {
			return err
		}
		for _, r := range all {
			if contains(slugs, r.Slug) {
				out = append(out, r)
			}
		}
		return nil
	})
	return
}
func (d DBRoleStore) RolePermissions(ctx context.Context, tid, rid string) (out [][2]string, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { out, err = store.ListRolePermissions(ctx, tx, tid, rid); return err })
	return
}
func (d DBRoleStore) ReplaceBindings(ctx context.Context, tid, uid, by string, ids []string) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { return store.ReplaceRoleBindings(ctx, tx, tid, uid, by, ids) })
}
func (d DBRoleStore) CountWithRole(ctx context.Context, tid, slug string) (n int, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { n, err = store.CountUsersWithRole(ctx, tx, tid, slug); return err })
	return
}

// DBPermissionStore is the database PermissionStore.
type DBPermissionStore struct{ St *store.Store }

func (d DBPermissionStore) UpsertPermission(ctx context.Context, tid, res, act, desc, by string) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { return store.UpsertPermission(ctx, tx, tid, res, act, desc, by) })
}
func (d DBPermissionStore) ListPermissions(ctx context.Context, tid string) (out [][3]string, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { out, err = store.ListPermissions(ctx, tx, tid); return err })
	return
}

// DBRoleCRUDStore is the database RoleCRUDStore.
type DBRoleCRUDStore struct{ DBRoleStore }

func (d DBRoleCRUDStore) tx(ctx context.Context, tid string, fn func(pgx.Tx) error) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, fn)
}
func (d DBRoleCRUDStore) InsertRole(ctx context.Context, r store.Role) error {
	return d.tx(ctx, r.TenantID, func(tx pgx.Tx) error { return store.InsertRole(ctx, tx, r) })
}
func (d DBRoleCRUDStore) Role(ctx context.Context, tid, id string) (r store.Role, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { r, err = store.GetRole(ctx, tx, tid, id); return err })
	return
}
func (d DBRoleCRUDStore) ListRoles(ctx context.Context, tid string) (out []store.Role, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListRoles(ctx, tx, tid); return err })
	return
}
func (d DBRoleCRUDStore) UpdateRoleName(ctx context.Context, tid, id, name string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.UpdateRoleName(ctx, tx, tid, id, name) })
}
func (d DBRoleCRUDStore) RemoveRole(ctx context.Context, tid, id string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.RemoveRole(ctx, tx, tid, id) })
}
func (d DBRoleCRUDStore) ReplaceRolePermissions(ctx context.Context, tid, rid string, perms [][2]string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.ReplaceRolePermissions(ctx, tx, tid, rid, perms) })
}
func (d DBRoleCRUDStore) RoleAssignees(ctx context.Context, tid, rid string) (out []string, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT user_id FROM role_bindings WHERE tenant_id = $1 AND role_id = $2", tid, rid)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var uid string
			if err := rows.Scan(&uid); err != nil {
				return err
			}
			out = append(out, uid)
		}
		return rows.Err()
	})
	return
}
func (d DBRoleCRUDStore) ListPermissions(ctx context.Context, tid string) (out [][3]string, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListPermissions(ctx, tx, tid); return err })
	return
}

// DBStatusStore is the database StatusStore.
type DBStatusStore struct{ DBRoleStore }

func (d DBStatusStore) UserStatus(ctx context.Context, tid, uid string) (status string, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		u, err := store.GetUser(ctx, tx, tid, uid)
		if err != nil {
			return err
		}
		status = u.Status
		return nil
	})
	return
}
func (d DBStatusStore) TenantStatus(ctx context.Context, tid string) (status string, err error) {
	err = d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		t, err := store.GetTenant(ctx, tx, tid)
		if err != nil {
			return err
		}
		status = t.Status
		return nil
	})
	return
}
func (d DBStatusStore) ListPermissions(ctx context.Context, tid string) (out [][3]string, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { out, err = store.ListPermissions(ctx, tx, tid); return err })
	return
}

var _ = errors.New

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- groups (feature 004)

// DBGroupStore is the database authz.GroupStore; it embeds the role store so
// one value serves Groups, Assigner and Decider.
type DBGroupStore struct{ DBRoleStore }

func (d DBGroupStore) tx(ctx context.Context, tid string, fn func(pgx.Tx) error) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, fn)
}

func (d DBGroupStore) CreateGroup(ctx context.Context, g store.Group) error {
	return d.tx(ctx, g.TenantID, func(tx pgx.Tx) error { return store.InsertGroup(ctx, tx, g) })
}
func (d DBGroupStore) UpdateGroup(ctx context.Context, tid, id, name, description string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.UpdateGroup(ctx, tx, tid, id, name, description) })
}
func (d DBGroupStore) DeleteGroup(ctx context.Context, tid, id string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.DeleteGroup(ctx, tx, tid, id) })
}
func (d DBGroupStore) GetGroup(ctx context.Context, tid, id string) (g store.Group, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { g, err = store.GetGroup(ctx, tx, tid, id); return err })
	return
}
func (d DBGroupStore) ListGroups(ctx context.Context, tid, q string) (out []store.Group, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListGroups(ctx, tx, tid, q); return err })
	return
}
func (d DBGroupStore) GroupMemberCounts(ctx context.Context, tid string) (out map[string]int, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.GroupMemberCounts(ctx, tx, tid); return err })
	return
}
func (d DBGroupStore) CountGroupMembers(ctx context.Context, tid, gid string) (n int, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { n, err = store.CountGroupMembers(ctx, tx, tid, gid); return err })
	return
}
func (d DBGroupStore) ListGroupMembers(ctx context.Context, tid, gid string, after time.Time, limit int) (out []store.GroupMember, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListGroupMembers(ctx, tx, tid, gid, after, limit); return err })
	return
}
func (d DBGroupStore) AddGroupMembers(ctx context.Context, tid, gid, addedBy string, userIDs []string) (n int, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { n, err = store.AddGroupMembers(ctx, tx, tid, gid, addedBy, userIDs); return err })
	return
}
func (d DBGroupStore) RemoveGroupMember(ctx context.Context, tid, gid, uid string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.RemoveGroupMember(ctx, tx, tid, gid, uid) })
}
func (d DBGroupStore) IsGroupMember(ctx context.Context, tid, gid, uid string) (ok bool, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { ok, err = store.IsGroupMember(ctx, tx, tid, gid, uid); return err })
	return
}
func (d DBGroupStore) UserGroups(ctx context.Context, tid, uid string) (out []store.Group, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.UserGroups(ctx, tx, tid, uid); return err })
	return
}
func (d DBGroupStore) ReplaceGroupRoles(ctx context.Context, tid, gid, grantedBy string, roleIDs []string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.ReplaceGroupRoles(ctx, tx, tid, gid, grantedBy, roleIDs) })
}
func (d DBGroupStore) GroupRoles(ctx context.Context, tid, gid string) (out []store.Role, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.GroupRoles(ctx, tx, tid, gid); return err })
	return
}
func (d DBGroupStore) GroupRoleSlugs(ctx context.Context, tid string) (out map[string][]string, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.GroupRoleSlugs(ctx, tx, tid); return err })
	return
}

// EffectiveRoles is shared by the group store and the decision status store.
func (d DBRoleStore) EffectiveRoles(ctx context.Context, tid, uid string) (out []store.EffectiveRoleRow, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { out, err = store.EffectiveRoles(ctx, tx, tid, uid); return err })
	return
}
