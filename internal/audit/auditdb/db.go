// Package auditdb binds the audit package to the database. SQL bindings are
// kept apart from the security logic so the logic is unit-tested without a
// database; these bindings are covered by the tagged integration suite.
package auditdb

import (
	"context"
	"time"

	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/jackc/pgx/v5"
)

// DBQuerier reads from the database under the tenant scope.
type DBQuerier struct{ St *store.Store }

func (d DBQuerier) QueryAudit(ctx context.Context, tid, uid, et string, from, to, cursor time.Time, limit int) (out []store.AuditRow, err error) {
	err = d.St.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		out, err = store.QueryAudit(ctx, tx, tid, uid, et, from, to, cursor, limit)
		return err
	})
	return
}
