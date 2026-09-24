// Package userdb binds the user package to the database. SQL bindings are
// kept apart from the security logic so the logic is unit-tested without a
// database; these bindings are covered by the tagged integration suite.
package userdb

import (
	"context"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/jackc/pgx/v5"
)

// DBStore is the database-backed Store.
type DBStore struct{ St *store.Store }

func (d DBStore) TenantBySlug(ctx context.Context, slug string) (t store.Tenant, err error) {
	err = d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { t, err = store.GetTenantBySlug(ctx, tx, slug); return err })
	return
}
func (d DBStore) UserByEmail(ctx context.Context, tid, email string) (u store.User, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { u, err = store.GetUserByEmail(ctx, tx, tid, email); return err })
	return
}
func (d DBStore) Roles(ctx context.Context, tid, uid string) (out []string, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { out, err = store.EffectiveRoleSlugs(ctx, tx, tid, uid); return err })
	return
}
func (d DBStore) TouchSignin(ctx context.Context, tid, uid string) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { return store.TouchSignin(ctx, tx, tid, uid) })
}
func (d DBStore) SetPasswordHash(ctx context.Context, tid, uid, hash string) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { return store.SetPassword(ctx, tx, tid, uid, hash) })
}
func (d DBStore) Attempt(ctx context.Context, tid, uid, emailHash, ipHash, outcome, reason string) error {
	return d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		return store.InsertSigninAttempt(ctx, tx, tid, uid, emailHash, ipHash, outcome, reason)
	})
}

// DBAdminStore is the database AdminStore.
type DBAdminStore struct{ St *store.Store }

func (d DBAdminStore) User(ctx context.Context, tid, id string) (u store.User, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { u, err = store.GetUser(ctx, tx, tid, id); return err })
	return
}
func (d DBAdminStore) UserAnyTenant(ctx context.Context, id string) (u store.User, err error) {
	err = d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT id, tenant_id, status FROM users WHERE id = $1", id).Scan(&u.ID, &u.TenantID, &u.Status)
	})
	if err != nil {
		err = store.ErrNotFound
	}
	return
}
func (d DBAdminStore) ListUsers(ctx context.Context, tid, q, status string, limit int) (out []store.User, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { out, err = store.ListUsers(ctx, tx, tid, q, status, limit); return err })
	return
}
func (d DBAdminStore) UpdateUserStatus(ctx context.Context, tid, id, status string) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { return store.UpdateUserStatus(ctx, tx, tid, id, status) })
}

// DeleteImportedUser deletes a user only while imported (feature 016).
func (d DBAdminStore) DeleteImportedUser(ctx context.Context, tid, id string) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { return store.DeleteImportedUser(ctx, tx, tid, id) })
}
func (d DBAdminStore) UserGroups(ctx context.Context, tid, uid string) (out []store.Group, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { out, err = store.UserGroups(ctx, tx, tid, uid); return err })
	return
}
func (d DBAdminStore) Roles(ctx context.Context, tid, uid string) (out []string, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { out, err = store.EffectiveRoleSlugs(ctx, tx, tid, uid); return err })
	return
}
func (d DBAdminStore) CountWithRole(ctx context.Context, tid, slug string) (n int, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { n, err = store.CountUsersWithRole(ctx, tx, tid, slug); return err })
	return
}

// ---------------------------------------------------------------- profiles & avatars (feature 004)

func (d DBAdminStore) UpdateProfile(ctx context.Context, tid, id string, p store.ProfilePatch) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { return store.UpdateProfile(ctx, tx, tid, id, p) })
}
func (d DBAdminStore) LookupProfiles(ctx context.Context, tid string, ids []string) (out []store.PublicProfile, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { out, err = store.LookupProfiles(ctx, tx, tid, ids); return err })
	return
}
func (d DBAdminStore) ListActiveMemberIDs(ctx context.Context, tid, after string, limit int, ids []string) (out []string, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		out, err = store.ListActiveMemberIDs(ctx, tx, tid, after, limit, ids)
		return err
	})
	return
}
func (d DBAdminStore) SearchProfiles(ctx context.Context, tid, q string, limit int) (out []store.PublicProfile, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { out, err = store.SearchProfiles(ctx, tx, tid, q, limit); return err })
	return
}
func (d DBAdminStore) UpsertAvatar(ctx context.Context, a store.Avatar) error {
	return d.St.Tx(ctx, store.Scope{TenantID: a.TenantID}, func(tx pgx.Tx) error { return store.UpsertAvatar(ctx, tx, a) })
}
func (d DBAdminStore) DeleteAvatar(ctx context.Context, tid, uid string) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { return store.DeleteAvatar(ctx, tx, tid, uid) })
}
func (d DBAdminStore) GetAvatar(ctx context.Context, tid, uid, id string) (a store.Avatar, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { a, err = store.GetAvatar(ctx, tx, tid, uid, id); return err })
	return
}
