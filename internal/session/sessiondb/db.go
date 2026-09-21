// Package sessiondb binds the session package to the database. It is kept apart
// from the security logic so that logic can be unit-tested to 100 % without
// a database; these bindings are covered by the tagged integration suite.
package sessiondb

import (
	"context"
	"time"

	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/jackc/pgx/v5"
)

// DBStore is the database-backed Store. Cross-tenant lookups (by secret hash,
// the feed) run under the system scope; everything else is tenant-scoped.
type DBStore struct{ St *store.Store }

func (d DBStore) tx(ctx context.Context, tid string, fn func(pgx.Tx) error) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, fn)
}
func (d DBStore) sys(ctx context.Context, fn func(pgx.Tx) error) error {
	return d.St.Tx(ctx, store.Scope{System: true}, fn)
}
func (d DBStore) Insert(ctx context.Context, s store.Session) error {
	return d.tx(ctx, s.TenantID, func(tx pgx.Tx) error { return store.InsertSession(ctx, tx, s) })
}
func (d DBStore) GetByHash(ctx context.Context, hash []byte) (s store.Session, err error) {
	err = d.sys(ctx, func(tx pgx.Tx) error { s, err = store.GetSessionBySecretHash(ctx, tx, hash); return err })
	return
}
func (d DBStore) Get(ctx context.Context, tid, id string) (s store.Session, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { s, err = store.GetSession(ctx, tx, tid, id); return err })
	return
}
func (d DBStore) ListUser(ctx context.Context, tid, uid string) (out []store.Session, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListUserSessions(ctx, tx, tid, uid); return err })
	return
}
func (d DBStore) Touch(ctx context.Context, tid, id string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.TouchSession(ctx, tx, tid, id) })
}
func (d DBStore) Revoke(ctx context.Context, tid, id, reason string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.RevokeSession(ctx, tx, tid, id, reason) })
}
func (d DBStore) RevokeUser(ctx context.Context, tid, uid, reason, keep string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.RevokeUserSessions(ctx, tx, tid, uid, reason, keep) })
}
func (d DBStore) RevokeTenant(ctx context.Context, tid, reason string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.RevokeTenantSessions(ctx, tx, tid, reason) })
}
func (d DBStore) InsertRevocation(ctx context.Context, r store.Revocation) error {
	return d.sys(ctx, func(tx pgx.Tx) error { return store.InsertRevocation(ctx, tx, r) })
}
func (d DBStore) RevocationsSince(ctx context.Context, since time.Time, limit int) (out []store.Revocation, err error) {
	err = d.sys(ctx, func(tx pgx.Tx) error { out, err = store.ListRevocationsSince(ctx, tx, since, limit); return err })
	return
}
func (d DBStore) Tenant(ctx context.Context, tid string) (t store.Tenant, err error) {
	err = d.sys(ctx, func(tx pgx.Tx) error { t, err = store.GetTenant(ctx, tx, tid); return err })
	return
}
func (d DBStore) Roles(ctx context.Context, tid, uid string) (out []string, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.EffectiveRoleSlugs(ctx, tx, tid, uid); return err })
	return
}
func (d DBStore) User(ctx context.Context, tid, uid string) (u store.User, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { u, err = store.GetUser(ctx, tx, tid, uid); return err })
	return
}
