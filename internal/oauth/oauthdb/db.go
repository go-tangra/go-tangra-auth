// Package oauthdb binds the oauth package to the database. SQL bindings are
// kept apart from the security logic so the logic is unit-tested without a
// database; these bindings are covered by the tagged integration suite.
package oauthdb

import (
	"context"

	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/jackc/pgx/v5"
)

// DBClients reads client applications from the database (system scope: the
// client id arrives before any tenant is known).
type DBClients struct{ St *store.Store }

func (d DBClients) Client(ctx context.Context, id string) (c store.ClientApplication, err error) {
	err = d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { c, err = store.GetClient(ctx, tx, id); return err })
	return
}
