package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/token"
)

// Each VerifyEnrollment failure maps to exactly one audit reason and one wire
// reason; anything not a time-window refusal stays enrollment_token_invalid.
func TestVerifyRefusalReasons(t *testing.T) {
	for _, c := range []struct {
		err         error
		audit, wire string
	}{
		{fmt.Errorf("%w: exp", token.ErrEnrollmentExpired), "enrollment_expired", EnrollTokenExpired},
		{fmt.Errorf("%w: nbf", token.ErrEnrollmentNotYetValid), "enrollment_not_yet_valid", EnrollTokenNotYetValid},
		{errors.New("token: signature is invalid"), "enrollment_invalid", EnrollTokenInvalid},
	} {
		if a, w := verifyRefusal(c.err); a != c.audit || w != c.wire {
			t.Fatalf("%v: got %s/%s", c.err, a, w)
		}
	}
}

// An unverifiable token is refused Unauthenticated with the closed reason as
// the status message (never the token) and audited as enrollment_invalid,
// before the jti store is touched.
func TestVerifyEnrollmentTokenInvalid(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{3}, 32))
	ring := token.NewRing(token.NewMemKeys(), env, token.Config{})
	if err := ring.Load(ctx); err != nil {
		t.Fatal(err)
	}
	srv := &EnrollmentServer{Tokens: token.NewIssuer(ring, "https://auth.example.org"), Audit: aw}

	const bad = "eyJhbGciOiJFZERTQSJ9.e30.c2ln"
	_, err := srv.VerifyEnrollmentToken(ctx, &authv1.VerifyEnrollmentTokenRequest{Token: bad})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated || st.Message() != EnrollTokenInvalid || strings.Contains(err.Error(), bad) {
		t.Fatalf("invalid token: %v", err)
	}
	aw.Flush()
	n := 0
	for _, r := range ms.AuditRows {
		if r.EventType == string(audit.TokenExchanged) && r.Outcome == "refused" && r.Reason == "enrollment_invalid" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("enrollment_invalid audited %d times", n)
	}
}
