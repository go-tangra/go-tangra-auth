package directorydb

import (
	"context"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/directory"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// errNoTenant refuses a tenant-scoped call without a tenant: an empty
// app.tenant_id would silently match no rows instead of failing.
var errNoTenant = errors.New("directorydb: tenant id required")

// errScope refuses an Atomic call under anything but a tenant scope.
var errScope = errors.New("directorydb: tenant scope required")

// DBStore adapts the database to directory.Store.
type DBStore struct{ St *store.Store }

var _ directory.Store = DBStore{}

// Atomic runs fn in one transaction under store.Scope{TenantID}, handing it a
// directory.ImportTx (the per-entry import transaction). Only a plain tenant
// scope is accepted: row-level security confines every statement to it.
func (d DBStore) Atomic(ctx context.Context, scope store.Scope, fn func(any) error) error {
	if scope.System || scope.Operator || scope.OperatorGrant != "" {
		return errScope
	}
	return d.tenantTx(ctx, scope.TenantID, func(tx pgx.Tx) error { return fn(directory.ImportTx(dbTx{tx})) })
}

// tenantTx runs fn in one transaction under store.Scope{TenantID}.
func (d DBStore) tenantTx(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	if tenantID == "" {
		return errNoTenant
	}
	return d.St.Tx(ctx, store.Scope{TenantID: tenantID}, fn)
}

// InsertDirectoryConnection stores a new connection in its tenant.
func (d DBStore) InsertDirectoryConnection(ctx context.Context, c store.DirectoryConnection) error { //nolint:gocritic // value signature fixed by directory.Store
	return d.tenantTx(ctx, c.TenantID, func(tx pgx.Tx) error { return store.InsertDirectoryConnection(ctx, tx, c) })
}

// GetDirectoryConnection reads one connection of the tenant.
func (d DBStore) GetDirectoryConnection(ctx context.Context, tenantID, id string) (out store.DirectoryConnection, err error) {
	err = d.tenantTx(ctx, tenantID, func(tx pgx.Tx) error {
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
	err = d.tenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		out, err = store.ListDirectoryConnections(ctx, tx, tenantID)
		return err
	})
	return out, err
}

// CountDirectoryConnections counts the tenant's connections (per-tenant cap).
func (d DBStore) CountDirectoryConnections(ctx context.Context, tenantID string) (n int, err error) {
	err = d.tenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		n, err = store.CountDirectoryConnections(ctx, tx, tenantID)
		return err
	})
	return n, err
}

// UpdateDirectoryConnection rewrites a connection of its tenant.
func (d DBStore) UpdateDirectoryConnection(ctx context.Context, c store.DirectoryConnection) error { //nolint:gocritic // value signature fixed by directory.Store
	return d.tenantTx(ctx, c.TenantID, func(tx pgx.Tx) error { return store.UpdateDirectoryConnection(ctx, tx, c) })
}

// SetDirectoryConnectionTest records the last test outcome.
func (d DBStore) SetDirectoryConnectionTest(ctx context.Context, tenantID, id, outcome string, at time.Time) error {
	return d.tenantTx(ctx, tenantID, func(tx pgx.Tx) error { return store.SetDirectoryConnectionTest(ctx, tx, tenantID, id, outcome, at) })
}

// DeleteDirectoryConnection removes a connection; imported users are kept.
func (d DBStore) DeleteDirectoryConnection(ctx context.Context, tenantID, id string) error {
	return d.tenantTx(ctx, tenantID, func(tx pgx.Tx) error { return store.DeleteDirectoryConnection(ctx, tx, tenantID, id) })
}

// UsersByEmails returns the tenant's users for the given e-mails, keyed by
// the stored e-mail (case-insensitive match).
func (d DBStore) UsersByEmails(ctx context.Context, tenantID string, emails []string) (out map[string]store.User, err error) {
	err = d.tenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		out, err = store.UsersByEmails(ctx, tx, tenantID, emails)
		return err
	})
	return out, err
}

// LinksByUIDs returns one connection's links for the given directory uids.
func (d DBStore) LinksByUIDs(ctx context.Context, tenantID, connID string, uids []string) (out map[string]store.DirectoryLink, err error) {
	err = d.tenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		out, err = store.LinksByUIDs(ctx, tx, tenantID, connID, uids)
		return err
	})
	return out, err
}

// User reads one user of the tenant.
func (d DBStore) User(ctx context.Context, tenantID, id string) (out store.User, err error) {
	err = d.tenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		out, err = store.GetUser(ctx, tx, tenantID, id)
		return err
	})
	return out, err
}

// dbTx is the per-entry import transaction (directory.ImportTx).
type dbTx struct{ tx pgx.Tx }

func (d dbTx) UserByEmail(ctx context.Context, tenantID, email string) (store.User, error) {
	return store.GetUserByEmail(ctx, d.tx, tenantID, email)
}

func (d dbTx) User(ctx context.Context, tenantID, id string) (store.User, error) {
	return store.GetUser(ctx, d.tx, tenantID, id)
}

func (d dbTx) LinksByUIDs(ctx context.Context, tenantID, connID string, uids []string) (map[string]store.DirectoryLink, error) {
	return store.LinksByUIDs(ctx, d.tx, tenantID, connID, uids)
}

// InsertUser creates an imported user: no password, no MFA, and the
// display-name flag stored as decoded (store.InsertUser would re-derive it
// and mark a "First Last" fallback as chosen by hand). A taken e-mail is
// store.ErrConflict.
func (d dbTx) InsertUser(ctx context.Context, u store.User) error { //nolint:gocritic // value signature fixed by directory.ImportTx
	_, err := d.tx.Exec(ctx, `INSERT INTO users (id, tenant_id, email, display_name, status, first_name, last_name, display_name_explicit)
		VALUES ($1,$2,$3,$4,'imported',$5,$6,$7)`,
		u.ID, u.TenantID, u.Email, u.DisplayName, u.FirstName, u.LastName, u.DisplayNameExplicit)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return store.ErrConflict
	}
	return err
}

func (d dbTx) UpdateImportedUser(ctx context.Context, tenantID, userID string, p store.ImportedProfile) error { //nolint:gocritic // value signature fixed by directory.ImportTx
	return store.UpdateImportedUser(ctx, d.tx, tenantID, userID, p)
}

func (d dbTx) UpsertLink(ctx context.Context, l store.DirectoryLink) error { //nolint:gocritic // value signature fixed by directory.ImportTx
	return store.UpsertLink(ctx, d.tx, l)
}
