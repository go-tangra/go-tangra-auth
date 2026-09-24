package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-tangra/go-tangra-auth/v4/internal/app"
	"github.com/go-tangra/go-tangra-auth/v4/internal/config"
)

// bootstrap prepares a deployment: the platform tenant (MFA mandatory by
// policy), its built-in roles, the first operator invitation (queued by
// e-mail and printed as an accept link) and the initial signing key. It is
// idempotent and replaces any seed script.
func bootstrap(args []string) int {
	fs := flag.NewFlagSet("authsvc bootstrap", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	email := fs.String("operator-email", "", "email address of the first platform operator (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *email == "" {
		return fail(fmt.Errorf("bootstrap: -operator-email is required"))
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Bootstrap never serves: bind ephemeral ports so it can run next to a live service.
	cfg.Server.GRPCAddr, cfg.Admin.Addr, cfg.Edge.Addr = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	if cfg.Server.HTTPAddr != "" {
		cfg.Server.HTTPAddr = "127.0.0.1:0"
	}
	a, err := app.Build(ctx, cfg, app.Options{Migrate: true})
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	res, err := a.Bootstrap(ctx, *email)
	if err != nil {
		return fail(err)
	}
	if err := a.SeedAllConsolePermissions(ctx); err != nil {
		return fail(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
	return 0
}
