// Package emaildb binds the email package to the database. SQL bindings are
// kept apart from the security logic so the logic is unit-tested without a
// database; these bindings are covered by the tagged integration suite.
package emaildb

import (
	"context"
	"time"

	"github.com/go-freya/freya/services/auth/internal/email"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/jackc/pgx/v5"
)

// StoreQueue is the outbox table behind the Queue interface.
type StoreQueue struct{ Store *store.Store }

func (q StoreQueue) Claim(ctx context.Context, limit int, backoff time.Duration) ([]email.Item, error) {
	var out []email.Item
	err := q.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		items, err := store.ClaimOutbox(ctx, tx, limit, backoff)
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
