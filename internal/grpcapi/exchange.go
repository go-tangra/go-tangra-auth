package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/go-freya/freya/authn"
	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
	"github.com/go-freya/freya/services/auth/internal/token"
)

const nilTenant = "00000000-0000-0000-0000-000000000000"

func callerService(ctx context.Context) string {
	if p, ok := authn.FromContext(ctx); ok {
		return p.ID.String()
	}
	return ""
}

func sessionIdentity(a tenantctx.Actor) *authv1.SessionIdentity {
	return &authv1.SessionIdentity{UserId: a.UserID, TenantId: a.TenantID, SessionId: a.SessionID, Roles: nonNilStrings(a.Roles), Amr: nonNilStrings(a.AMR), Operator: a.Kind == tenantctx.KindOperator,
		DisplayName: a.DisplayName, AvatarUrl: a.AvatarURL}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// mint issues a token for a resolved actor.
func (s *SessionsServer) mint(ctx context.Context, a tenantctx.Actor, audience, op string) (string, *timestamppb.Timestamp, error) {
	tok, c, err := s.Tokens.Issue(token.Request{UserID: a.UserID, TenantID: a.TenantID, SessionID: a.SessionID, Roles: a.Roles, AMR: a.AMR, Audience: audience})
	if err != nil {
		s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: a.TenantID, ActorKind: "service", ActorService: callerService(ctx), SubjectKind: "session", SubjectID: a.SessionID, Outcome: "failed", Reason: op + "_mint_failed"})
		return "", nil, status.Error(codes.Unavailable, "token unavailable")
	}
	s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: a.TenantID, ActorKind: "service", ActorService: callerService(ctx), SubjectKind: "session", SubjectID: a.SessionID, Outcome: "ok", Reason: op, Details: map[string]any{"audience": audience}})
	return tok, timestamppb.New(c.ExpiresAt.Time), nil
}

// Exchange resolves a session cookie like the console path and mints a token.
func (s *SessionsServer) Exchange(ctx context.Context, req *authv1.ExchangeRequest) (*authv1.ExchangeResponse, error) {
	a, err := s.Sessions.Resolve(ctx, req.GetCookieSecret())
	if err != nil {
		s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: nilTenant, ActorKind: "service", ActorService: callerService(ctx), Outcome: "refused", Reason: "no_session"})
		return nil, status.Error(codes.Unauthenticated, "no_session")
	}
	tok, exp, err := s.mint(ctx, a, req.GetAudience(), "exchange")
	if err != nil {
		return nil, err
	}
	return &authv1.ExchangeResponse{Identity: sessionIdentity(a), AccessToken: tok, ExpiresAt: exp}, nil
}

// MintToken refreshes a token for a session that is still live.
func (s *SessionsServer) MintToken(ctx context.Context, req *authv1.MintTokenRequest) (*authv1.MintTokenResponse, error) {
	a, err := s.Sessions.ByID(ctx, req.GetTenantId(), req.GetSessionId())
	if err != nil {
		s.emit(audit.Event{Type: audit.TokenExchanged, TenantID: nilTenant, ActorKind: "service", ActorService: callerService(ctx), SubjectKind: "session", SubjectID: req.GetSessionId(), Outcome: "refused", Reason: "no_session"})
		return nil, status.Error(codes.Unauthenticated, "no_session")
	}
	tok, exp, err := s.mint(ctx, a, req.GetAudience(), "mint")
	if err != nil {
		return nil, err
	}
	return &authv1.MintTokenResponse{Identity: sessionIdentity(a), AccessToken: tok, ExpiresAt: exp}, nil
}
