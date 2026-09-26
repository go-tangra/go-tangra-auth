package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/permref"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// PermissionsCLI implements the operator commands of feature 019:
//
//	authsvc permissions verify [-tenant id] [-snapshot f] [-compare f]
//	authsvc permissions prune-legacy [-dry-run]
//	authsvc modules retire <name>
//
// Reports are JSON on Out; the exit code is 1 on a loss or a refusal.
type PermissionsCLI struct {
	V       *authz.Verifier
	Modules *authz.Modules
	Tenants func(ctx context.Context) ([]string, error)
	Out     io.Writer
}

// PermissionsCLI wires the commands against the running store.
func (a *App) PermissionsCLI(out io.Writer) PermissionsCLI {
	return PermissionsCLI{V: a.Verifier, Modules: a.Modules, Tenants: a.activeTenantIDs, Out: out}
}

func (c PermissionsCLI) print(v any) error {
	enc := json.NewEncoder(c.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (c PermissionsCLI) tenants(ctx context.Context, tenant string) ([]string, error) {
	if tenant != "" {
		if !tenantctx.ValidTenantID(tenant) {
			return nil, fmt.Errorf("permissions: malformed tenant id %q", tenant)
		}
		return []string{tenant}, nil
	}
	return c.Tenants(ctx)
}

// Verify runs one of: -snapshot (record effective permissions to a file,
// mode 0600), -compare (check a snapshot: no loss), or the default check
// (legacy grants against module-scoped grants). Exit 1 on any loss.
func (c PermissionsCLI) Verify(ctx context.Context, tenant, snapshot, compare string) (int, error) {
	ctx = tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	tenants, err := c.tenants(ctx, tenant)
	if err != nil {
		return 1, err
	}
	switch {
	case snapshot != "":
		snap, err := c.V.Snapshot(ctx, tenants)
		if err != nil {
			return 1, err
		}
		js, err := json.MarshalIndent(snap, "", "  ")
		if err != nil {
			return 1, err
		}
		if err := os.WriteFile(snapshot, js, 0o600); err != nil {
			return 1, err
		}
		users := 0
		for _, u := range snap {
			users += len(u)
		}
		return 0, c.print(map[string]any{"snapshot": snapshot, "tenants": len(snap), "users": users})
	case compare != "":
		js, err := os.ReadFile(compare)
		if err != nil {
			return 1, err
		}
		var before authz.Snapshot
		if err := json.Unmarshal(js, &before); err != nil {
			return 1, fmt.Errorf("permissions: snapshot %s: %w", compare, err)
		}
		if tenant != "" {
			before = authz.Snapshot{tenant: before[tenant]}
		}
		rep, err := c.V.Compare(ctx, before)
		if err != nil {
			return 1, err
		}
		return exitOn(rep), c.print(rep)
	}
	rep, err := c.V.Verify(ctx, tenants)
	if err != nil {
		return 1, err
	}
	return exitOn(rep), c.print(struct {
		authz.Report
		PruneReady bool `json:"prune_ready"`
	}{rep, rep.Clean()})
}

func exitOn(rep authz.Report) int {
	if rep.Losses() > 0 {
		return 1
	}
	return 0
}

// Prune removes the legacy permissions of every active tenant once verify is
// clean (no loss, no pending grant, no drift); -dry-run only counts.
func (c PermissionsCLI) Prune(ctx context.Context, dryRun bool) (int, error) {
	ctx = tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	tenants, err := c.Tenants(ctx)
	if err != nil {
		return 1, err
	}
	res, err := c.V.PruneLegacy(ctx, tenants, dryRun)
	if errors.Is(err, authz.ErrPruneRefused) {
		rep, verr := c.V.Verify(ctx, tenants)
		if verr != nil {
			return 1, verr
		}
		return 1, c.print(struct {
			Refused string `json:"refused"`
			authz.Report
		}{err.Error(), rep})
	}
	if err != nil {
		return 1, err
	}
	return 0, c.print(struct {
		authz.PruneResult
		DryRun bool `json:"dry_run"`
	}{res, dryRun})
}

// RetireModule retires a module removed from the platform.
func (c PermissionsCLI) RetireModule(ctx context.Context, name string) (int, error) {
	if !permref.ValidModule(name) {
		return 1, fmt.Errorf("modules: malformed module name %q", name)
	}
	slugs, err := c.Modules.RetireModule(ctx, name)
	if err != nil {
		return 1, err
	}
	if slugs == nil {
		slugs = []string{}
	}
	return 0, c.print(map[string]any{"module": name, "retired_roles": slugs})
}
