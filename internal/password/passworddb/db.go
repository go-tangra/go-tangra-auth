// Package passworddb binds the password package to the database. It is kept apart
// from the security logic so that logic can be unit-tested to 100 % without
// a database; these bindings are covered by the tagged integration suite.
package passworddb

import (
	"context"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/jackc/pgx/v5"
)

// DBChangeStore is the database ChangeStore.
type DBChangeStore struct{ St *store.Store }

func (d DBChangeStore) User(ctx context.Context, tid, uid string) (u store.User, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { u, err = store.GetUser(ctx, tx, tid, uid); return err })
	return
}
func (d DBChangeStore) Tenant(ctx context.Context, tid string) (t store.Tenant, err error) {
	err = d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { t, err = store.GetTenant(ctx, tx, tid); return err })
	return
}
func (d DBChangeStore) SetPassword(ctx context.Context, tid, uid, hash string) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { return store.SetPassword(ctx, tx, tid, uid, hash) })
}

// DBRecoveryStore is the database RecoveryStore.
type DBRecoveryStore struct{ St *store.Store }

func (d DBRecoveryStore) TenantBySlug(ctx context.Context, slug string) (t store.Tenant, err error) {
	err = d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { t, err = store.GetTenantBySlug(ctx, tx, slug); return err })
	return
}
func (d DBRecoveryStore) Tenant(ctx context.Context, tid string) (t store.Tenant, err error) {
	err = d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { t, err = store.GetTenant(ctx, tx, tid); return err })
	return
}
func (d DBRecoveryStore) UserByEmail(ctx context.Context, tid, e string) (u store.User, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { u, err = store.GetUserByEmail(ctx, tx, tid, e); return err })
	return
}
func (d DBRecoveryStore) InsertRecoveryRequest(ctx context.Context, r store.RecoveryRequest, ip string) error {
	return d.St.Tx(ctx, store.Scope{TenantID: r.TenantID}, func(tx pgx.Tx) error { return store.InsertRecoveryRequest(ctx, tx, r, ip) })
}
func (d DBRecoveryStore) PeekRecovery(ctx context.Context, hash string) (r store.RecoveryRequest, err error) {
	err = d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, tenant_id, user_id, token_hash, expires_at FROM recovery_requests WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`, hash).
			Scan(&r.ID, &r.TenantID, &r.UserID, &r.TokenHash, &r.ExpiresAt)
	})
	if err != nil {
		err = store.ErrNotFound
	}
	return
}
func (d DBRecoveryStore) UseRecoveryRequest(ctx context.Context, hash string) (r store.RecoveryRequest, err error) {
	err = d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { r, err = store.UseRecoveryRequest(ctx, tx, hash); return err })
	return
}
func (d DBRecoveryStore) SetPassword(ctx context.Context, tid, uid, hash string) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { return store.SetPassword(ctx, tx, tid, uid, hash) })
}
func (d DBRecoveryStore) Enqueue(ctx context.Context, it store.OutboxItem) error {
	return d.St.Tx(ctx, store.Scope{TenantID: it.TenantID}, func(tx pgx.Tx) error { return store.EnqueueOutbox(ctx, tx, it) })
}
