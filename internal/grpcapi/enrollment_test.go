package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

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

func newEnrollSrv(t *testing.T) *EnrollmentServer {
	t.Helper()
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{3}, 32))
	ring := token.NewRing(token.NewMemKeys(), env, token.Config{})
	if err := ring.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &EnrollmentServer{Tokens: token.NewIssuer(ring, "https://auth.example.org")}
}

// MintEnrollmentToken accepts up to 24 h and refuses a longer ttl with
// InvalidArgument naming the maximum (never a silently shorter token).
func TestMintEnrollmentTokenLifetime(t *testing.T) {
	ctx := context.Background()
	srv := newEnrollSrv(t)
	const sid = "spiffe://example.org/svc/sms"
	before := time.Now()
	resp, err := srv.MintEnrollmentToken(ctx, &authv1.MintEnrollmentTokenRequest{TenantId: "t1", SpiffePaths: []string{sid}, TtlSeconds: 24 * 3600})
	if err != nil {
		t.Fatalf("24h: %v", err)
	}
	if exp := resp.GetExpiresAt().AsTime(); exp.Before(before.Add(24*time.Hour-time.Second)) || exp.After(time.Now().Add(24*time.Hour+time.Second)) {
		t.Fatalf("24h expiry %v", exp)
	}
	_, err = srv.MintEnrollmentToken(ctx, &authv1.MintEnrollmentTokenRequest{TenantId: "t1", SpiffePaths: []string{sid}, TtlSeconds: 24*3600 + 1})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument || !strings.Contains(st.Message(), "24h") {
		t.Fatalf("24h+1s: %v", err)
	}
	// Other refusals keep their generic message.
	_, err = srv.MintEnrollmentToken(ctx, &authv1.MintEnrollmentTokenRequest{TenantId: "", SpiffePaths: []string{sid}})
	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument || st.Message() != "enrollment token could not be minted" {
		t.Fatalf("no tenant: %v", err)
	}
}

// TokenStatus answers from the jti ledger: consumed with its time, unconsumed
// and unknown as consumed=false, a non-UUID jti as InvalidArgument (the ledger
// is never asked), a ledger failure as Unavailable.
func TestTokenStatus(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 10, 9, 30, 0, 0, time.UTC)
	const used, fresh = "0192a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", "0192a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c"
	asked := 0
	srv := newEnrollSrv(t)
	srv.ConsumedAt = func(_ context.Context, jti string) (time.Time, bool, error) {
		asked++
		switch jti {
		case used:
			return at, true, nil
		case "0192a1b2-c3d4-7e5f-8a9b-ffffffffffff":
			return time.Time{}, false, errors.New("db down")
		}
		return time.Time{}, false, nil
	}

	r, err := srv.TokenStatus(ctx, &authv1.TokenStatusRequest{Jti: used})
	if err != nil || !r.GetConsumed() || !r.GetConsumedAt().AsTime().Equal(at) {
		t.Fatalf("consumed: %+v %v", r, err)
	}
	for _, jti := range []string{fresh, "00000000-0000-0000-0000-000000000000"} {
		r, err = srv.TokenStatus(ctx, &authv1.TokenStatusRequest{Jti: jti})
		if err != nil || r.GetConsumed() || r.GetConsumedAt() != nil {
			t.Fatalf("not consumed %s: %+v %v", jti, r, err)
		}
	}
	n := asked
	for _, jti := range []string{"", "j", "not-a-uuid", used + "x", "0192a1b2c3d47e5f8a9b0c1d2e3f4a5b", strings.Repeat("a", 4096)} {
		_, err = srv.TokenStatus(ctx, &authv1.TokenStatusRequest{Jti: jti})
		if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
			t.Fatalf("malformed %q: %v", jti, err)
		}
	}
	if asked != n {
		t.Fatal("a malformed jti reached the ledger")
	}
	_, err = srv.TokenStatus(ctx, &authv1.TokenStatusRequest{Jti: "0192a1b2-c3d4-7e5f-8a9b-ffffffffffff"})
	if st, _ := status.FromError(err); st.Code() != codes.Unavailable || strings.Contains(st.Message(), "db down") {
		t.Fatalf("ledger failure: %v", err)
	}
}
