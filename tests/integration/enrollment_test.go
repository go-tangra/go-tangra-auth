//go:build integration

package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

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
	// TokenStatus: an unknown jti and a minted but unused one are unconsumed.
	jti := enrollJTI(t, mint.GetToken())
	for _, j := range []string{jti, "00000000-0000-0000-0000-0000000000ff"} {
		if st, err := srv.TokenStatus(ctx, &authv1.TokenStatusRequest{Jti: j}); err != nil || st.GetConsumed() || st.GetConsumedAt() != nil {
			t.Fatalf("status before use %s: %+v %v", j, st, err)
		}
	}
	before := time.Now().Add(-time.Minute)
	v, err := srv.VerifyEnrollmentToken(ctx, &authv1.VerifyEnrollmentTokenRequest{Token: mint.GetToken()})
	if err != nil || v.GetTenantId() != tenant || len(v.GetSpiffePaths()) != 1 || v.GetSpiffePaths()[0] != sid || v.GetJti() != jti {
		t.Fatalf("verify: %+v %v", v, err)
	}
	// ... and consumed, with its time, once verified.
	if st, err := srv.TokenStatus(ctx, &authv1.TokenStatusRequest{Jti: jti}); err != nil || !st.GetConsumed() || st.GetConsumedAt().AsTime().Before(before) || st.GetConsumedAt().AsTime().After(time.Now().Add(time.Minute)) {
		t.Fatalf("status after use: %+v %v", st, err)
	}
	if _, err := srv.TokenStatus(ctx, &authv1.TokenStatusRequest{Jti: "nope"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed jti: %v", err)
	}
	// replay: the jti is burned, so a second verify must fail single-use.
	// The status message is the closed reason lcm relays to the workload.
	_, err = srv.VerifyEnrollmentToken(ctx, &authv1.VerifyEnrollmentTokenRequest{Token: mint.GetToken()})
	if st, _ := status.FromError(err); st.Code() != codes.Unauthenticated || st.Message() != grpcapi.EnrollTokenUsed {
		t.Fatalf("replay must be Unauthenticated %s, got %v", grpcapi.EnrollTokenUsed, err)
	}
	// a garbage token is opaque: enrollment_token_invalid.
	_, err = srv.VerifyEnrollmentToken(ctx, &authv1.VerifyEnrollmentTokenRequest{Token: "x.y.z"})
	if st, _ := status.FromError(err); st.Code() != codes.Unauthenticated || st.Message() != grpcapi.EnrollTokenInvalid {
		t.Fatalf("garbage must be Unauthenticated %s, got %v", grpcapi.EnrollTokenInvalid, err)
	}
}

// enrollJTI reads the jti from a token's payload, as the gateway does.
func enrollJTI(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		JTI string `json:"jti"`
	}
	if err != nil || json.Unmarshal(raw, &c) != nil || c.JTI == "" {
		t.Fatalf("payload: %v", err)
	}
	return c.JTI
}
