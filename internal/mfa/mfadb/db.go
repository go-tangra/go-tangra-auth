// Package mfadb binds the mfa package to the database. It is kept apart
// from the security logic so that logic can be unit-tested to 100 % without
// a database; these bindings are covered by the tagged integration suite.
package mfadb

import (
	"context"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/jackc/pgx/v5"
)

// DBStore is the database Store.
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
func (d DBStore) SetMFA(ctx context.Context, tid, uid string, on bool, enc []byte) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.SetMFA(ctx, tx, tid, uid, on, enc) })
}
func (d DBStore) SetMFACounter(ctx context.Context, tid, uid string, c int64) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.SetMFACounter(ctx, tx, tid, uid, c) })
}
func (d DBStore) ReplaceRecoveryCodes(ctx context.Context, tid, uid string, hashes []string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.ReplaceRecoveryCodes(ctx, tx, tid, uid, hashes) })
}
func (d DBStore) ListRecoveryCodeHashes(ctx context.Context, tid, uid string) (out []string, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListRecoveryCodeHashes(ctx, tx, tid, uid); return err })
	return
}
func (d DBStore) UseRecoveryCode(ctx context.Context, tid, uid, hash string) error {
	return d.tx(ctx, tid, func(tx pgx.Tx) error { return store.UseRecoveryCode(ctx, tx, tid, uid, hash) })
}
func (d DBStore) ListWebAuthnCredentials(ctx context.Context, tid, uid string) (out []store.WebAuthnCredential, err error) {
	err = d.tx(ctx, tid, func(tx pgx.Tx) error { out, err = store.ListWebAuthnCredentials(ctx, tx, tid, uid); return err })
	return
}
