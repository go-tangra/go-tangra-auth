// Package emaildb binds the email package to the database. SQL bindings are
// kept apart from the security logic so the logic is unit-tested without a
// database; these bindings are covered by the tagged integration suite.
package emaildb

import (
	"context"

	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/jackc/pgx/v5"
)

// StoreQueue is the outbox table behind the Queue interface.
type StoreQueue struct{ Store *store.Store }

func (q StoreQueue) Claim(ctx context.Context, limit int) ([]email.Item, error) {
	var out []email.Item
	err := q.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		items, err := store.ClaimOutbox(ctx, tx, limit)
		if err != nil {
			return err
		}
		for _, it := range items {
			out = append(out, email.Item{ID: it.ID, TenantID: it.TenantID, Kind: it.Kind, To: it.ToEmail, PayloadEnc: it.PayloadEnc, Attempts: it.Attempts})
		}
		return nil
	})
	return out, err
}

func (q StoreQueue) MarkSent(ctx context.Context, id string) error {
	return q.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { return store.MarkOutboxSent(ctx, tx, id) })
}

func (q StoreQueue) MarkFailed(ctx context.Context, id, reason string) error {
	return q.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error { return store.MarkOutboxFailed(ctx, tx, id, reason) })
}
