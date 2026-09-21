// Package tokendb binds the token package to the database. It is kept apart
// from the security logic so that logic can be unit-tested to 100 % without
// a database; these bindings are covered by the tagged integration suite.
package tokendb

import (
	"context"
	"time"

	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/jackc/pgx/v5"
)

// StoreKeys is the database KeyStore (system scope).
type StoreKeys struct{ St *store.Store }

func (s StoreKeys) List(ctx context.Context) (keys []store.SigningKey, err error) {
	err = s.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { keys, err = store.ListSigningKeys(ctx, tx); return err })
	return
}
func (s StoreKeys) Insert(ctx context.Context, k store.SigningKey) error {
	return s.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { return store.InsertSigningKey(ctx, tx, k) })
}
func (s StoreKeys) SetState(ctx context.Context, kid, state string, _ time.Time) error {
	return s.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { return store.SetSigningKeyState(ctx, tx, kid, state) })
}
func (s StoreKeys) Remove(ctx context.Context, kid string) error {
	return s.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { return store.RemoveSigningKey(ctx, tx, kid) })
}
