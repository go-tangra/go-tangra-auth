package grpcapi

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/token"
)

// Refusal reasons of VerifyEnrollmentToken: the codes.Unauthenticated status
// message is exactly one of these (a closed vocabulary, like "no_session"), so
// lcm can tell the enrolling workload why its join token was refused without a
// proto change. The token itself is never echoed.
const (
	EnrollTokenExpired     = "enrollment_token_expired"
	EnrollTokenNotYetValid = "enrollment_token_not_yet_valid"
	EnrollTokenUsed        = "enrollment_token_used"
	EnrollTokenInvalid     = "enrollment_token_invalid" // signature, kid, issuer, audience, lifetime, claims, malformed
)

// verifyRefusal maps a VerifyEnrollment failure to its audit reason and wire
// reason. Only the time window is told apart; everything else stays opaque.
func verifyRefusal(err error) (auditReason, wire string) {
	switch {
	case errors.Is(err, token.ErrEnrollmentExpired):
		return "enrollment_expired", EnrollTokenExpired
	case errors.Is(err, token.ErrEnrollmentNotYetValid):
		return "enrollment_not_yet_valid", EnrollTokenNotYetValid
	}
	return "enrollment_invalid", EnrollTokenInvalid
}

// EnrollmentServer mints and verifies single-use lcm enrollment (join) tokens:
// the credential a workload presents to lcm for its FIRST SVID. Every method
// is policed by the auth policy (mint: gateway/console; verify: lcm; status:
// gateway).
type EnrollmentServer struct {
	authv1.UnimplementedEnrollmentServer
	Tokens *token.Issuer
	Store  *store.Store
	Audit  *audit.Writer
	// ConsumedAt answers TokenStatus from the jti ledger (nil = Store).
	ConsumedAt func(ctx context.Context, jti string) (time.Time, bool, error)
}

// jtiRE is an enrollment token's jti: a UUID (store.NewID).
var jtiRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (s *EnrollmentServer) emit(e audit.Event) {
	if s.Audit != nil {
		_ = s.Audit.Emit(e)
	}
}

// MintEnrollmentToken issues a single-use, short-lived enrollment token.
func (s *EnrollmentServer) MintEnrollmentToken(ctx context.Context, req *authv1.MintEnrollmentTokenRequest) (*authv1.MintEnrollmentTokenResponse, error) {
	tok, grant, err := s.Tokens.IssueEnrollment(req.GetTenantId(), req.GetSpiffePaths(), secs(req.GetTtlSeconds()))
	if err != nil {
		reason, msg := "enrollment_mint_failed", "enrollment token could not be minted"
		if errors.Is(err, token.ErrEnrollmentLifetime) {
			reason, msg = "enrollment_lifetime_exceeded", "ttl_seconds exceeds the maximum enrollment token lifetime of "+token.MaxEnrollLifetime.String()
		}
		s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: req.GetTenantId(), ActorKind: "service", ActorService: callerService(ctx), Outcome: "failed", Reason: reason})
		return nil, status.Error(codes.InvalidArgument, msg)
	}
	s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: grant.TenantID, ActorKind: "service", ActorService: callerService(ctx), Outcome: "ok", Reason: "enrollment_mint", Details: map[string]any{"jti": grant.JTI, "spiffe_paths": grant.SpiffePaths}})
	return &authv1.MintEnrollmentTokenResponse{Token: tok, ExpiresAt: timestamppb.New(grant.ExpiresAt)}, nil
}

// VerifyEnrollmentToken validates a token and BURNS its jti (single-use).
func (s *EnrollmentServer) VerifyEnrollmentToken(ctx context.Context, req *authv1.VerifyEnrollmentTokenRequest) (*authv1.VerifyEnrollmentTokenResponse, error) {
	grant, err := s.Tokens.VerifyEnrollment(req.GetToken())
	if err != nil {
		reason, wire := verifyRefusal(err)
		s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: nilTenant, ActorKind: "service", ActorService: callerService(ctx), Outcome: "refused", Reason: reason})
		return nil, status.Error(codes.Unauthenticated, wire)
	}
	burnErr := s.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		return store.ConsumeEnrollmentJTI(ctx, tx, grant.JTI, grant.TenantID, grant.ExpiresAt)
	})
	if burnErr != nil {
		reason, code, wire := "enrollment_burn_failed", codes.Unavailable, "enrollment token cannot be used"
		if errors.Is(burnErr, store.ErrConflict) {
			reason, code, wire = "enrollment_replayed", codes.Unauthenticated, EnrollTokenUsed
		}
		s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: grant.TenantID, ActorKind: "service", ActorService: callerService(ctx), Outcome: "refused", Reason: reason})
		return nil, status.Error(code, wire)
	}
	s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: grant.TenantID, ActorKind: "service", ActorService: callerService(ctx), Outcome: "ok", Reason: "enrollment_verify", Details: map[string]any{"jti": grant.JTI}})
	return &authv1.VerifyEnrollmentTokenResponse{TenantId: grant.TenantID, SpiffePaths: grant.SpiffePaths, Jti: grant.JTI}, nil
}

// TokenStatus reports whether an enrollment token's jti was used and when. An
// unknown jti (never used, or pruned after expiry) is consumed=false. It reads
// only; nothing is audited.
func (s *EnrollmentServer) TokenStatus(ctx context.Context, req *authv1.TokenStatusRequest) (*authv1.TokenStatusResponse, error) {
	jti := req.GetJti()
	if !jtiRE.MatchString(jti) {
		return nil, status.Error(codes.InvalidArgument, "jti must be a UUID")
	}
	lookup := s.ConsumedAt
	if lookup == nil {
		lookup = s.storeConsumedAt
	}
	at, consumed, err := lookup(ctx, jti)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "enrollment token status unavailable")
	}
	if !consumed {
		return &authv1.TokenStatusResponse{}, nil
	}
	return &authv1.TokenStatusResponse{Consumed: true, ConsumedAt: timestamppb.New(at)}, nil
}

func (s *EnrollmentServer) storeConsumedAt(ctx context.Context, jti string) (at time.Time, consumed bool, err error) {
	err = s.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		var e error
		at, consumed, e = store.EnrollmentJTIConsumedAt(ctx, tx, jti)
		return e
	})
	return at, consumed, err
}
