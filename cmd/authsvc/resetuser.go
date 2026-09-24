package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-freya/freya/services/auth/internal/app"
	"github.com/go-freya/freya/services/auth/internal/config"
)

// resetUser is the break-glass recovery for a locked-out user (lost password
// or MFA device): it clears their credentials, revokes their sessions and
// prints a fresh invitation link that keeps their roles. It needs direct
// database access, so it is run by the operator on the host, e.g.
//
//	docker compose -p freya-stack run --rm auth-bootstrap reset-user -config deploy/container.yaml -email admin@example.org
func resetUser(args []string) int {
	fs := flag.NewFlagSet("authsvc reset-user", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	userEmail := fs.String("email", "", "email address of the user to reset (required)")
	tenant := fs.String("tenant", app.PlatformTenantSlug, "tenant slug of the user")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *userEmail == "" {
		return fail(fmt.Errorf("reset-user: -email is required"))
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Like bootstrap, never serve: bind ephemeral ports next to the live service.
	cfg.Server.GRPCAddr, cfg.Admin.Addr, cfg.Edge.Addr = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	if cfg.Server.HTTPAddr != "" {
		cfg.Server.HTTPAddr = "127.0.0.1:0"
	}
	a, err := app.Build(ctx, cfg, app.Options{})
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	res, err := a.ResetUser(ctx, *tenant, *userEmail)
	if err != nil {
		return fail(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	return 0
}
