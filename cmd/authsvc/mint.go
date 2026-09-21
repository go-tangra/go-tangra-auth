package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-freya/freya/services/auth/internal/app"
	"github.com/go-freya/freya/services/auth/internal/config"
)

// meshTenant is lcm's mesh CA tenant: an enrollment token must name it so the
// SVID lcm issues chains to the ONE mesh root every workload trusts. (Matches
// services/lcm/internal/app.MeshTenantID.)
const meshTenant = "00000000-0000-0000-0000-000000000001"

// mintEnrollmentToken mints a single-use lcm enrollment (join) token offline,
// using the same signing keys the running auth service publishes. It never
// serves. Intended for the dev bootstrap that hands each service its first-
// enrollment credential; in production the gateway/console mints these.
func mintEnrollmentToken(args []string) int {
	fs := flag.NewFlagSet("authsvc mint-enrollment-token", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	spiffe := fs.String("spiffe", "", "SPIFFE id(s) the token authorises, comma-separated (required)")
	tenant := fs.String("tenant", meshTenant, "tenant id the SVID is issued under (default: the lcm mesh tenant)")
	ttl := fs.Duration("ttl", 10*time.Minute, "token lifetime")
	out := fs.String("out", "", "write the token to this file (0600); default stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *spiffe == "" {
		return fail(errors.New("mint-enrollment-token: -spiffe is required"))
	}
	var paths []string
	for _, p := range strings.Split(*spiffe, ",") {
		if p = strings.TrimSpace(p); p != "" {
			paths = append(paths, p)
		}
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	cfg.Server.GRPCAddr, cfg.Admin.Addr, cfg.Edge.Addr = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	if cfg.Server.HTTPAddr != "" {
		cfg.Server.HTTPAddr = "127.0.0.1:0"
	}
	ctx := context.Background()
	a, err := app.Build(ctx, cfg, app.Options{Migrate: false})
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	tok, grant, err := a.Tokens.IssueEnrollment(*tenant, paths, *ttl)
	if err != nil {
		return fail(err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(tok), 0o600); err != nil {
			return fail(err)
		}
		fmt.Fprintf(os.Stderr, "wrote enrollment token to %s (jti %s, exp %s) for %v\n", *out, grant.JTI, grant.ExpiresAt.UTC().Format(time.RFC3339), paths)
	} else {
		fmt.Println(tok)
	}
	return 0
}
