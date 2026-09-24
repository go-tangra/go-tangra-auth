package grpcapi

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/token"
)

// EnrollmentServer mints and verifies single-use lcm enrollment (join) tokens:
// the credential a workload presents to lcm for its FIRST SVID. Both methods
// are policed by the auth policy (mint: gateway/console; verify: lcm).
type EnrollmentServer struct {
	authv1.UnimplementedEnrollmentServer
	Tokens *token.Issuer
	Store  *store.Store
	Audit  *audit.Writer
}

func (s *EnrollmentServer) emit(e audit.Event) {
	if s.Audit != nil {
		_ = s.Audit.Emit(e)
	}
}

// MintEnrollmentToken issues a single-use, short-lived enrollment token.
func (s *EnrollmentServer) MintEnrollmentToken(ctx context.Context, req *authv1.MintEnrollmentTokenRequest) (*authv1.MintEnrollmentTokenResponse, error) {
	tok, grant, err := s.Tokens.IssueEnrollment(req.GetTenantId(), req.GetSpiffePaths(), secs(req.GetTtlSeconds()))
	if err != nil {
		s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: req.GetTenantId(), ActorKind: "service", ActorService: callerService(ctx), Outcome: "failed", Reason: "enrollment_mint_failed"})
		return nil, status.Error(codes.InvalidArgument, "enrollment token could not be minted")
	}
	s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: grant.TenantID, ActorKind: "service", ActorService: callerService(ctx), Outcome: "ok", Reason: "enrollment_mint", Details: map[string]any{"jti": grant.JTI, "spiffe_paths": grant.SpiffePaths}})
	return &authv1.MintEnrollmentTokenResponse{Token: tok, ExpiresAt: timestamppb.New(grant.ExpiresAt)}, nil
}

// VerifyEnrollmentToken validates a token and BURNS its jti (single-use).
func (s *EnrollmentServer) VerifyEnrollmentToken(ctx context.Context, req *authv1.VerifyEnrollmentTokenRequest) (*authv1.VerifyEnrollmentTokenResponse, error) {
	grant, err := s.Tokens.VerifyEnrollment(req.GetToken())
	if err != nil {
		s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: nilTenant, ActorKind: "service", ActorService: callerService(ctx), Outcome: "refused", Reason: "enrollment_invalid"})
		return nil, status.Error(codes.Unauthenticated, "invalid enrollment token")
	}
	burnErr := s.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		return store.ConsumeEnrollmentJTI(ctx, tx, grant.JTI, grant.TenantID, grant.ExpiresAt)
	})
	if burnErr != nil {
		reason, code := "enrollment_burn_failed", codes.Unavailable
		if errors.Is(burnErr, store.ErrConflict) {
			reason, code = "enrollment_replayed", codes.Unauthenticated
		}
		s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: grant.TenantID, ActorKind: "service", ActorService: callerService(ctx), Outcome: "refused", Reason: reason})
		return nil, status.Error(code, "enrollment token cannot be used")
	}
	s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: grant.TenantID, ActorKind: "service", ActorService: callerService(ctx), Outcome: "ok", Reason: "enrollment_verify", Details: map[string]any{"jti": grant.JTI}})
	return &authv1.VerifyEnrollmentTokenResponse{TenantId: grant.TenantID, SpiffePaths: grant.SpiffePaths, Jti: grant.JTI}, nil
}
