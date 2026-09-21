package app

import (
	"context"
	"fmt"
	"time"

	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
	"github.com/go-freya/freya/services/auth/pkg/authmanifest"
	"github.com/go-freya/freya/services/gateway/pkg/gatewayclient"
)

// seedConsolePermissions registers the console permissions in a tenant and
// grants them to the builtin roles (idempotent).
func (a *App) seedConsolePermissions(ctx context.Context, tenantID string) error {
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	defs := make([]authz.Permission, 0, len(authmanifest.Permissions))
	for _, p := range authmanifest.Permissions {
		defs = append(defs, authz.Permission{Resource: p.Resource, Action: p.Action, Description: p.Description})
	}
	if _, err := a.Registry.Register(sys, tenantID, "auth", defs); err != nil {
		return fmt.Errorf("register console permissions: %w", err)
	}
	for slug, refs := range authmanifest.Grants {
		if err := a.Roles.GrantBuiltin(sys, tenantID, slug, refs); err != nil {
			return fmt.Errorf("grant %s: %w", slug, err)
		}
	}
	return nil
}

// SeedAllConsolePermissions seeds every active tenant (start-up, bootstrap).
func (a *App) SeedAllConsolePermissions(ctx context.Context) error {
	ids, err := a.activeTenantIDs(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := a.seedConsolePermissions(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// runGatewayMode seeds permissions, then registers with the gateway and
// renews the lease until ctx ends.
func (a *App) runGatewayMode(ctx context.Context) {
	for ctx.Err() == nil {
		if err := a.SeedAllConsolePermissions(ctx); err == nil {
			break
		} else {
			a.Log.Warn("console permission seeding failed; retrying", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
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
