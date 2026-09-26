package app

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// BuiltinRolesFor returns the built-in roles of a tenant kind (feature 019,
// research D6): customer tenants owner, admin, member, auditor; the platform
// tenant owner, admin, operator, auditor.
func BuiltinRolesFor(kind string) []string {
	if kind == "platform" {
		return append([]string(nil), platformBuiltinRoles...)
	}
	return append([]string(nil), tenant.BuiltinRoles...)
}

// EnsureBuiltinRoles is the idempotent start-up reconciliation that gives
// every existing tenant the built-in roles of its kind (auditor did not exist
// before feature 019). SQL cannot write OpenFGA, so it runs in the service.
func (a *App) EnsureBuiltinRoles(ctx context.Context) error {
	var tenants []store.Tenant
	if err := a.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		var err error
		tenants, err = store.ListTenants(ctx, tx)
		return err
	}); err != nil {
		return err
	}
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	for _, t := range tenants {
		changed, err := a.Roles.EnsureBuiltin(sys, t.ID, BuiltinRolesFor(t.Kind))
		if err != nil {
			return err
		}
		if len(changed) > 0 {
			a.Log.Info("built-in roles ensured", "tenant", t.ID, "roles", changed)
		}
	}
	return nil
}
