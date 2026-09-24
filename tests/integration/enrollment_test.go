//go:build integration

package integration

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/grpcapi"
)

// TestEnrollmentTokenMintVerifyReplay exercises the auth enrollment-token
// authority against a real Postgres: mint -> verify (grant returned) -> replay
// is rejected (single-use jti burn).
func TestEnrollmentTokenMintVerifyReplay(t *testing.T) {
	e := Start(t)
	srv := &grpcapi.EnrollmentServer{Tokens: e.App.Tokens, Store: e.App.Store, Audit: e.App.Audit}
	ctx := context.Background()
	const tenant = "00000000-0000-0000-0000-000000000001"
	const sid = "spiffe://example.org/svc/notification"

	mint, err := srv.MintEnrollmentToken(ctx, &authv1.MintEnrollmentTokenRequest{TenantId: tenant, SpiffePaths: []string{sid}, TtlSeconds: 300})
	if err != nil || mint.GetToken() == "" {
		t.Fatalf("mint: %v", err)
	}
	v, err := srv.VerifyEnrollmentToken(ctx, &authv1.VerifyEnrollmentTokenRequest{Token: mint.GetToken()})
	if err != nil || v.GetTenantId() != tenant || len(v.GetSpiffePaths()) != 1 || v.GetSpiffePaths()[0] != sid || v.GetJti() == "" {
		t.Fatalf("verify: %+v %v", v, err)
	}
	// replay: the jti is burned, so a second verify must fail single-use.
	if _, err := srv.VerifyEnrollmentToken(ctx, &authv1.VerifyEnrollmentTokenRequest{Token: mint.GetToken()}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("replay must be Unauthenticated, got %v", err)
	}
}
