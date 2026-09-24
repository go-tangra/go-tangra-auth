// Package tenantdb binds the tenant package to the database. SQL bindings are
// kept apart from the security logic so the logic is unit-tested without a
// database; these bindings are covered by the tagged integration suite.
package tenantdb

import (
	"context"
	"errors"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/jackc/pgx/v5"
)

// DBStore is the database Store (system scope: operators span tenants).
type DBStore struct{ St *store.Store }

func (d DBStore) sys(ctx context.Context, fn func(pgx.Tx) error) error {
	return d.St.Tx(ctx, store.Scope{System: true}, fn)
}
func (d DBStore) InsertTenant(ctx context.Context, t store.Tenant) error {
	return d.sys(ctx, func(tx pgx.Tx) error { return store.InsertTenant(ctx, tx, t) })
}
func (d DBStore) Tenant(ctx context.Context, id string) (t store.Tenant, err error) {
	err = d.sys(ctx, func(tx pgx.Tx) error { t, err = store.GetTenant(ctx, tx, id); return err })
	return
}
func (d DBStore) ListTenants(ctx context.Context) (out []store.Tenant, err error) {
	err = d.sys(ctx, func(tx pgx.Tx) error { out, err = store.ListTenants(ctx, tx); return err })
	return
}
func (d DBStore) UpdateTenantStatus(ctx context.Context, id, status string) error {
	return d.sys(ctx, func(tx pgx.Tx) error { return store.UpdateTenantStatus(ctx, tx, id, status) })
}
func (d DBStore) UpdateTenantPolicy(ctx context.Context, id string, policy []byte) error {
	return d.sys(ctx, func(tx pgx.Tx) error { return store.UpdateTenantPolicy(ctx, tx, id, policy) })
}
func (d DBStore) InsertRole(ctx context.Context, r store.Role) error {
	return d.sys(ctx, func(tx pgx.Tx) error { return store.InsertRole(ctx, tx, r) })
}

// DBGrantStore is the database GrantStore.
type DBGrantStore struct{ DBStore }

func (d DBGrantStore) InsertOperatorGrant(ctx context.Context, g store.OperatorGrant) error {
	return d.sys(ctx, func(tx pgx.Tx) error { return store.InsertOperatorGrant(ctx, tx, g) })
}
func (d DBGrantStore) ActiveOperatorGrant(ctx context.Context, op, tid string) (g store.OperatorGrant, err error) {
	err = d.sys(ctx, func(tx pgx.Tx) error { g, err = store.ActiveOperatorGrant(ctx, tx, op, tid); return err })
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		err = store.ErrNotFound
	}
	return
}
