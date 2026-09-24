package directorydb

import (
	"context"
	"errors"
	"time"

	"github.com/go-freya/freya/services/auth/internal/directory"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/jackc/pgx/v5"
)

// errNoTenant refuses a tenant-scoped call without a tenant: an empty
// app.tenant_id would silently match no rows instead of failing.
var errNoTenant = errors.New("directorydb: tenant id required")

// DBStore adapts the database to directory.Store.
type DBStore struct{ St *store.Store }

var _ directory.Store = DBStore{}

// Atomic runs fn in one transaction under store.Scope{TenantID}, so row-level
// security confines every statement in fn to that tenant.
func (d DBStore) Atomic(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	if tenantID == "" {
		return errNoTenant
	}
	return d.St.Tx(ctx, store.Scope{TenantID: tenantID}, fn)
}

// InsertDirectoryConnection stores a new connection in its tenant.
func (d DBStore) InsertDirectoryConnection(ctx context.Context, c store.DirectoryConnection) error { //nolint:gocritic // value signature fixed by directory.Store
	return d.Atomic(ctx, c.TenantID, func(tx pgx.Tx) error { return store.InsertDirectoryConnection(ctx, tx, c) })
}

// GetDirectoryConnection reads one connection of the tenant.
func (d DBStore) GetDirectoryConnection(ctx context.Context, tenantID, id string) (out store.DirectoryConnection, err error) {
	err = d.Atomic(ctx, tenantID, func(tx pgx.Tx) error {
		out, err = store.GetDirectoryConnection(ctx, tx, tenantID, id)
		return err
	})
	return out, err
}

// GetDirectoryConnectionAnyTenant runs under the system scope. It exists only
// so the service can audit a cross-tenant id; callers must never return the
// row to the requester.
func (d DBStore) GetDirectoryConnectionAnyTenant(ctx context.Context, id string) (out store.DirectoryConnection, err error) {
	err = d.St.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		out, err = store.GetDirectoryConnectionAnyTenant(ctx, tx, id)
		return err
	})
	return out, err
}

// ListDirectoryConnections lists the tenant's connections.
func (d DBStore) ListDirectoryConnections(ctx context.Context, tenantID string) (out []store.DirectoryConnection, err error) {
	err = d.Atomic(ctx, tenantID, func(tx pgx.Tx) error {
		out, err = store.ListDirectoryConnections(ctx, tx, tenantID)
		return err
	})
	return out, err
}

// CountDirectoryConnections counts the tenant's connections (per-tenant cap).
func (d DBStore) CountDirectoryConnections(ctx context.Context, tenantID string) (n int, err error) {
	err = d.Atomic(ctx, tenantID, func(tx pgx.Tx) error {
		n, err = store.CountDirectoryConnections(ctx, tx, tenantID)
		return err
	})
	return n, err
}

// UpdateDirectoryConnection rewrites a connection of its tenant.
func (d DBStore) UpdateDirectoryConnection(ctx context.Context, c store.DirectoryConnection) error { //nolint:gocritic // value signature fixed by directory.Store
	return d.Atomic(ctx, c.TenantID, func(tx pgx.Tx) error { return store.UpdateDirectoryConnection(ctx, tx, c) })
}

// SetDirectoryConnectionTest records the last test outcome.
func (d DBStore) SetDirectoryConnectionTest(ctx context.Context, tenantID, id, outcome string, at time.Time) error {
	return d.Atomic(ctx, tenantID, func(tx pgx.Tx) error { return store.SetDirectoryConnectionTest(ctx, tx, tenantID, id, outcome, at) })
}

// DeleteDirectoryConnection removes a connection; imported users are kept.
func (d DBStore) DeleteDirectoryConnection(ctx context.Context, tenantID, id string) error {
	return d.Atomic(ctx, tenantID, func(tx pgx.Tx) error { return store.DeleteDirectoryConnection(ctx, tx, tenantID, id) })
}
