package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra-auth/v4/internal/token"
)

// CodeTTL bounds the authorization code lifetime.
const CodeTTL = 60 * time.Second

// Refusals.
var (
	ErrInvalidRequest = errors.New("invalid_request")
	ErrInvalidGrant   = errors.New("invalid_grant")
	ErrInvalidClient  = errors.New("invalid_client")
)

// ClientSource looks up registered applications.
type ClientSource interface {
	Client(ctx context.Context, clientID string) (store.ClientApplication, error)
}

// Service issues and redeems codes.
type Service struct {
	clients ClientSource
	cache   *cache.Cache
	tokens  *token.Issuer
	audit   *audit.Writer
	now     func() time.Time
}

// New wires the service.
func New(clients ClientSource, c *cache.Cache, t *token.Issuer, a *audit.Writer) *Service {
	return &Service{clients: clients, cache: c, tokens: t, audit: a, now: time.Now}
}

// AuthorizeRequest are the validated /authorize query parameters.
type AuthorizeRequest struct {
	ResponseType, ClientID, RedirectURI, State, CodeChallenge, CodeChallengeMethod string
}

// ParseAuthorize validates the query strictly (every parameter required).
func ParseAuthorize(q url.Values) (AuthorizeRequest, error) {
	r := AuthorizeRequest{ResponseType: q.Get("response_type"), ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), State: q.Get("state"),
		CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method")}
	switch {
	case r.ResponseType != "code", r.ClientID == "", r.RedirectURI == "", r.State == "", r.CodeChallengeMethod != "S256",
		len(r.CodeChallenge) != 43, len(r.State) > 512, len(r.ClientID) > 128:
		return AuthorizeRequest{}, ErrInvalidRequest
	}
	if u, err := url.Parse(r.RedirectURI); err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
		return AuthorizeRequest{}, ErrInvalidRequest
	}
	return r, nil
}

// ValidateClient checks the client exists and the redirect URI is registered
// (exact string match).
func (s *Service) ValidateClient(ctx context.Context, r AuthorizeRequest) (store.ClientApplication, error) {
	c, err := s.clients.Client(ctx, r.ClientID)
	if err != nil {
		return store.ClientApplication{}, ErrInvalidRequest
	}
	for _, u := range c.RedirectURIs {
		if u == r.RedirectURI {
			return c, nil
		}
	}
	return store.ClientApplication{}, ErrInvalidRequest
}

type pending struct {
	ClientID, RedirectURI, Challenge string
	TenantID, UserID, SessionID      string
	Roles, AMR                       []string
}

// IssueCode binds a code to the signed-in actor and the request. The actor's
// tenant must own the client.
func (s *Service) IssueCode(ctx context.Context, actor tenantctx.Actor, c store.ClientApplication, r AuthorizeRequest) (string, error) {
	if actor.TenantID != c.TenantID {
		s.emit(audit.Event{Type: audit.CrossTenantRefused, TenantID: c.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: "oauth_client_tenant",
			Details: map[string]any{"actor_tenant": actor.TenantID, "client_id": c.ClientID}})
		return "", ErrInvalidRequest
	}
	code, err := crypto.RandomToken(32)
	if err != nil {
		return "", err
	}
	p := pending{ClientID: c.ClientID, RedirectURI: r.RedirectURI, Challenge: r.CodeChallenge, TenantID: actor.TenantID, UserID: actor.UserID, SessionID: actor.SessionID, Roles: actor.Roles, AMR: actor.AMR}
	b, _ := json.Marshal(p)
	if err := s.cache.KV().Set(ctx, cache.CodeKey(crypto.HashToken(code)), string(b), CodeTTL); err != nil {
		return "", err
	}
	return code, nil
}

// TokenRequest are the form fields of POST /api/v1/oauth/token.
type TokenRequest struct {
	GrantType, Code, RedirectURI, ClientID, CodeVerifier, ClientSecret string
}

// TokenResponse is the RFC 6749 body.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// Redeem exchanges a code exactly once. Every failure is ErrInvalidGrant
// (or ErrInvalidClient for a bad secret) so callers learn nothing else.
func (s *Service) Redeem(ctx context.Context, r TokenRequest) (TokenResponse, error) {
	if r.GrantType != "authorization_code" || r.Code == "" || r.ClientID == "" || r.RedirectURI == "" {
		return TokenResponse{}, ErrInvalidRequest
	}
	key := cache.CodeKey(crypto.HashToken(r.Code))
	raw, ok, err := s.cache.KV().Get(ctx, key)
	if err != nil || !ok {
		return TokenResponse{}, ErrInvalidGrant
	}
	_ = s.cache.KV().Del(ctx, key) // single use, even when the exchange fails below
	var p pending
	if json.Unmarshal([]byte(raw), &p) != nil {
		return TokenResponse{}, ErrInvalidGrant
	}
	c, err := s.clients.Client(ctx, r.ClientID)
	if err != nil || p.ClientID != r.ClientID || p.RedirectURI != r.RedirectURI {
		return TokenResponse{}, ErrInvalidGrant
	}
	if !c.Public {
		if c.SecretHash == nil || r.ClientSecret == "" {
			return TokenResponse{}, ErrInvalidClient
		}
		if ok, _, err := crypto.VerifyPassword(r.ClientSecret, *c.SecretHash); err != nil || !ok {
			return TokenResponse{}, ErrInvalidClient
		}
	}
	if err := VerifyPKCE(r.CodeVerifier, p.Challenge); err != nil {
		return TokenResponse{}, ErrInvalidGrant
	}
	tok, claims, err := s.tokens.Issue(token.Request{UserID: p.UserID, TenantID: p.TenantID, SessionID: p.SessionID, Roles: p.Roles, AMR: p.AMR, Audience: c.ClientID})
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: tok, TokenType: "Bearer", ExpiresIn: int(claims.ExpiresAt.Sub(claims.IssuedAt.Time).Seconds())}, nil
}

func (s *Service) emit(e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Emit(e)
	}
}
