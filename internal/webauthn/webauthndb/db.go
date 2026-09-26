// Package webauthndb binds the webauthn package to the database. It is kept
// apart from the ceremony logic so that logic can be unit-tested to 100 %
// without a database; these bindings are covered by the tagged integration
// suite.
package webauthndb

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// DBStore is the database webauthn.Store.
type DBStore struct{ St *store.Store }

func (d DBStore) tx(ctx context.Context, tid string, fn func(pgx.Tx) error) error {
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, fn)
}
func (d DBStore) User(ctx context.Context, tid, uid string) (u store.User, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { u, err = store.GetUser(ctx, tx, tid, uid); return err })
	return
}
func (d DBStore) Tenant(ctx context.Context, tid string) (t store.Tenant, err error) {
	err = d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { t, err = store.GetTenant(ctx, tx, tid); return err })
	return
}
func (d DBStore) WebAuthnHandle(ctx context.Context, tid, uid string) (h []byte, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { h, err = store.WebAuthnHandle(ctx, tx, tid, uid); return err })
	return
}
func (d DBStore) EnsureWebAuthnHandle(ctx context.Context, tid, uid string, candidate []byte) (h []byte, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { h, err = store.EnsureWebAuthnHandle(ctx, tx, tid, uid, candidate); return err })
	return
}
func (d DBStore) ListWebAuthnCredentials(ctx context.Context, tid, uid string) (out []store.WebAuthnCredential, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListWebAuthnCredentials(ctx, tx, tid, uid); return err })
	return
}
func (d DBStore) InsertWebAuthnCredential(ctx context.Context, c store.WebAuthnCredential) error { //nolint:gocritic // row value
	return d.tx(ctx, c.TenantID, func(tx pgx.Tx) error { return store.InsertWebAuthnCredential(ctx, tx, c) })
}
func (d DBStore) RenameWebAuthnCredential(ctx context.Context, tid, uid, id, name string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.RenameWebAuthnCredential(ctx, tx, tid, uid, id, name) })
}
func (d DBStore) DeleteWebAuthnCredential(ctx context.Context, tid, uid, id string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.DeleteWebAuthnCredential(ctx, tx, tid, uid, id) })
}
func (d DBStore) UpdateWebAuthnUse(ctx context.Context, tid, id string, signCount int64, backupState bool) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.UpdateWebAuthnUse(ctx, tx, tid, id, signCount, backupState) })
}
func (d DBStore) FlagWebAuthnClone(ctx context.Context, tid, id string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.FlagWebAuthnClone(ctx, tx, tid, id) })
}
