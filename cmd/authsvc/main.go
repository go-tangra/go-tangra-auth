// Command authsvc runs the tenant authentication service (default) or
// bootstraps a deployment: `authsvc bootstrap -config deploy/dev.yaml
// -operator-email ops@example.org` creates the platform tenant, the first
// operator invitation and the initial signing key.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-freya/freya/services/auth/console"
	"github.com/go-freya/freya/services/auth/internal/app"
	"github.com/go-freya/freya/services/auth/internal/config"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "bootstrap" {
		os.Exit(bootstrap(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "mint-enrollment-token" {
		os.Exit(mintEnrollmentToken(os.Args[2:]))
	}
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("authsvc", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	noMigrate := fs.Bool("no-migrate", false, "do not apply database migrations on start")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	opts := app.Options{Migrate: !*noMigrate}
	if dist, ok := console.Dist(); ok {
		opts.Console = dist
	}
	if remote, ok := console.Remote(); ok {
		opts.Remote = remote
	}
	a, err := app.Build(ctx, cfg, opts)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	if e := a.HTTP.Edge(); e != nil {
		if ep, err := e.Endpoint(); err == nil {
			fmt.Fprintln(os.Stderr, "authsvc: edge listening on", ep.String())
		}
	} else if ep, err := a.Freya.HTTP().Endpoint(); err == nil {
		fmt.Fprintln(os.Stderr, "authsvc: gateway mode, browser API on", ep.String())
	}
	if ep, err := a.Freya.GRPC().Endpoint(); err == nil {
		fmt.Fprintln(os.Stderr, "authsvc: grpc listening on", ep.String())
	}
	if err := a.Run(ctx); err != nil {
		return fail(err)
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "authsvc:", err)
	return 1
}
