// Command downstream is the example service from quickstart §4: it verifies
// end-user access tokens offline with pkg/authclient (keys and revocations
// fetched from the auth service over the Freya channel) and echoes the
// identity behind demo.v1.Demo/WhoAmI.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-freya/freya"
	"github.com/go-freya/freya/authn"
	"github.com/go-freya/freya/config"
	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	demov1 "github.com/go-freya/freya/services/auth/api/proto/demo/v1"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type server struct {
	demov1.UnimplementedDemoServer
	authz authv1.AuthorizationClient
}

// permissions this service enforces; registered for every tenant at start.
var permissions = []*authv1.PermissionDef{{Resource: "demo", Action: "whoami", Description: "Call demo.v1.Demo/WhoAmI"}}

func (s server) WhoAmI(ctx context.Context, _ *demov1.WhoAmIRequest) (*demov1.WhoAmIResponse, error) {
	id, _ := authclient.FromContext(ctx)
	// Authentication proved who the user is; authorization asks whether they may.
	dec, err := s.authz.Check(ctx, &authv1.CheckRequest{TenantId: id.TenantID, UserId: id.UserID, Resource: "demo", Action: "whoami"})
	if err != nil {
		return nil, status.Error(codes.Unavailable, "authorization unavailable")
	}
	if !dec.GetAllowed() {
		return nil, status.Error(codes.PermissionDenied, dec.GetReason())
	}
	resp := &demov1.WhoAmIResponse{UserId: id.UserID, TenantId: id.TenantID, SessionId: id.SessionID, Roles: id.Roles, Amr: id.AMR}
	if peer, ok := authn.FromContext(ctx); ok {
		resp.CallerService = peer.ID.String()
	}
	return resp, nil
}

func main() {
	path := flag.String("config", "deploy/downstream.yaml", "Freya configuration")
	issuer := flag.String("issuer", "https://localhost:8443", "expected token issuer")
	authSvc := flag.String("auth-service", "auth", "service name of the auth service in discovery")
	flag.Parse()
	cfg, err := config.Load(*path)
	if err != nil {
		fail(err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	app, err := freya.New(cfg, freya.WithLogger(log.Handler()))
	if err != nil {
		fail(err)
	}
	defer app.Close()
	conn, err := app.Client(ctx, *authSvc)
	if err != nil {
		fail(err)
	}
	verifier := authclient.New(authclient.Config{Issuer: *issuer, RevocationPoll: 5 * time.Second},
		authclient.GRPCKeys{Client: authv1.NewKeysClient(conn)}, authclient.GRPCRevocations{Client: authv1.NewSessionsClient(conn), Limit: 500})
	if err := verifier.Start(ctx, func(err error) { log.Warn("authclient", "err", err) }); err != nil {
		fail(err)
	}
	authz := authv1.NewAuthorizationClient(conn)
	if _, err := authz.RegisterPermissions(ctx, &authv1.RegisterPermissionsRequest{Permissions: permissions}); err != nil {
		fail(fmt.Errorf("register permissions: %w", err))
	}
	// End-user authentication runs after the channel's service authn/authz.
	app.GRPC().Use("/demo.v1.Demo/*", authclient.KratosMiddleware(verifier))
	demov1.RegisterDemoServer(app.GRPC(), server{authz: authz})
	if ep, err := app.GRPC().Endpoint(); err == nil {
		fmt.Fprintln(os.Stderr, "downstream: listening", ep.String())
	}
	if err := app.Run(ctx); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "downstream:", err)
	os.Exit(1)
}
