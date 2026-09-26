package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-tangra/go-tangra-auth/v4/internal/app"
	"github.com/go-tangra/go-tangra-auth/v4/internal/config"
)

// permissions runs the module-scoped permission cut-over commands (feature
// 019), run by the operator on the host like reset-user:
//
//	authsvc permissions verify [-tenant id] [-snapshot f] [-compare f] -config c
//	authsvc permissions prune-legacy [-dry-run] -config c
func permissions(args []string) int {
	if len(args) == 0 {
		return fail(fmt.Errorf("permissions: verify or prune-legacy"))
	}
	fs := flag.NewFlagSet("authsvc permissions "+args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	var tenant, snapshot, compare *string
	var dryRun *bool
	switch args[0] {
	case "verify":
		tenant = fs.String("tenant", "", "tenant id (default: every active tenant)")
		snapshot = fs.String("snapshot", "", "write every user's effective permissions to this file")
		compare = fs.String("compare", "", "compare against a snapshot file: exit 1 on any loss")
	case "prune-legacy":
		dryRun = fs.Bool("dry-run", false, "count what would be removed")
	default:
		return fail(fmt.Errorf("permissions: unknown command %q (verify, prune-legacy)", args[0]))
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	return withCLIApp(*cfgPath, func(ctx context.Context, a *app.App) (int, error) {
		cli := a.PermissionsCLI(os.Stdout)
		if args[0] == "verify" {
			return cli.Verify(ctx, *tenant, *snapshot, *compare)
		}
		return cli.Prune(ctx, *dryRun)
	})
}

// modules runs `authsvc modules retire <name>`: the module's roles are
// retired in every tenant (grants and assignments kept) and its permissions
// leave the role editor.
func modules(args []string) int {
	if len(args) == 0 || args[0] != "retire" {
		return fail(fmt.Errorf("modules: retire <name>"))
	}
	fs := flag.NewFlagSet("authsvc modules retire", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		return fail(fmt.Errorf("modules retire: exactly one module name"))
	}
	return withCLIApp(*cfgPath, func(ctx context.Context, a *app.App) (int, error) {
		return a.PermissionsCLI(os.Stdout).RetireModule(ctx, fs.Arg(0))
	})
}

// withCLIApp builds the app without serving (ephemeral ports, like
// bootstrap and reset-user) and runs fn.
func withCLIApp(cfgPath string, fn func(ctx context.Context, a *app.App) (int, error)) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cfg.Server.GRPCAddr, cfg.Admin.Addr, cfg.Edge.Addr = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	if cfg.Server.HTTPAddr != "" {
		cfg.Server.HTTPAddr = "127.0.0.1:0"
	}
	a, err := app.Build(ctx, cfg, app.Options{})
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	code, err := fn(ctx, a)
	if err != nil {
		fmt.Fprintln(os.Stderr, "authsvc:", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}
