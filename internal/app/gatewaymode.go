package app

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra-auth/v4/pkg/authmanifest"
	"github.com/go-tangra/go-tangra-portal/sdk/v4/pkg/gatewayclient"
)

// authRegistration is auth's own registration as module "auth"
// ("Authentication"): the console permissions and their built-in grants.
func authRegistration(tenants []string) authz.Registration {
	reg := authz.Registration{Module: authz.AuthModule, DisplayName: authz.AuthDisplayName, Registrant: authz.AuthModule, Tenants: tenants}
	for _, p := range authmanifest.Permissions {
		reg.Permissions = append(reg.Permissions, authz.Permission{Resource: p.Resource, Action: p.Action, Description: p.Description})
	}
	slugs := make([]string, 0, len(authmanifest.Grants))
	for slug := range authmanifest.Grants {
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	for _, slug := range slugs {
		reg.Grants = append(reg.Grants, authz.BuiltinGrant{Role: slug, Permissions: authmanifest.Grants[slug]})
	}
	return reg
}

// seedConsolePermissions registers the console permissions in tenants and
// grants them to the built-in roles (idempotent). Built-in roles a tenant
// lacks (operator outside the platform tenant) are expected and not logged.
func (a *App) seedConsolePermissions(ctx context.Context, tenants []string) error {
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	if _, err := a.Modules.Register(sys, authRegistration(tenants)); err != nil {
		return fmt.Errorf("register console permissions: %w", err)
	}
	return nil
}

// SeedAllConsolePermissions ensures the built-in roles of every active
// tenant (auditor, feature 019) and seeds the console permissions (start-up,
// bootstrap).
func (a *App) SeedAllConsolePermissions(ctx context.Context) error {
	if err := a.EnsureBuiltinRoles(ctx); err != nil {
		return err
	}
	ids, err := a.activeTenantIDs(ctx)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	return a.seedConsolePermissions(ctx, ids)
}

// seedLoop seeds until it succeeds or ctx ends (start-up in both modes).
func (a *App) seedLoop(ctx context.Context) bool {
	for ctx.Err() == nil {
		err := a.SeedAllConsolePermissions(ctx)
		if err == nil {
			return true
		}
		a.Log.Warn("console permission seeding failed; retrying", "err", err)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(5 * time.Second):
		}
	}
	return false
}

// runGatewayMode seeds permissions, then registers with the gateway and
// renews the lease until ctx ends.
func (a *App) runGatewayMode(ctx context.Context) {
	if !a.seedLoop(ctx) {
		return
	}
	man, err := authmanifest.Manifest()
	if err != nil {
		a.Log.Error("gateway manifest", "err", err)
		return
	}
	httpEP, err := a.Freya.HTTP().Endpoint()
	if err != nil {
		a.Log.Error("gateway registration: http endpoint", "err", err)
		return
	}
	grpcEP, err := a.Freya.GRPC().Endpoint()
	if err != nil {
		a.Log.Error("gateway registration: grpc endpoint", "err", err)
		return
	}
	var client *gatewayclient.Client
	for ctx.Err() == nil && client == nil {
		conn, err := a.Freya.Client(ctx, a.Cfg.Gateway.Service)
		if err != nil {
			a.Log.Warn("gateway connection", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		client, err = gatewayclient.New(conn, gatewayclient.Options{Manifest: man, HTTPURL: "https://" + httpEP.Host, GRPCTarget: grpcEP.Host, Logger: a.Log,
			OnState: func(s gatewayclient.State) {
				a.Log.Info("gateway lease", "registered", s.Registered, "lease", s.LeaseID, "err", s.Err)
			}})
		if err != nil {
			a.Log.Error("gateway client", "err", err)
			return
		}
	}
	if client != nil {
		if err := client.Run(ctx); err != nil {
			a.Log.Error("gateway registration", "err", err)
		}
	}
}
