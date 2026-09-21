package oauth

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
	"github.com/go-freya/freya/services/auth/internal/token"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
)

func setup(t *testing.T) (*Service, *memstore.Store, *token.Ring) {
	t.Helper()
	ms := memstore.New()
	secret, _ := crypto.HashPassword("s3cret-value-for-confidential", crypto.DefaultParams)
	ms.AddClient(store.ClientApplication{ClientID: "spa", TenantID: tA, RedirectURIs: []string{"https://app.example.org/cb"}, Public: true})
	ms.AddClient(store.ClientApplication{ClientID: "backend", TenantID: tA, RedirectURIs: []string{"https://svc.example.org/cb"}, SecretHash: &secret})
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{4}, 32))
	ring := token.NewRing(token.NewMemKeys(), env, token.Config{})
	if err := ring.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	return New(ms, cache.New(cache.NewMemory()), token.NewIssuer(ring, "https://auth.example.org"), nil), ms, ring
}

func TestPKCE(t *testing.T) {
	v := strings.Repeat("a", 43)
	if err := VerifyPKCE(v, Challenge(v)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "!"} {
		if err := VerifyPKCE(bad, Challenge(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := VerifyPKCE(v, Challenge(v+"x")); err == nil {
		t.Fatal("mismatch accepted")
	}
	if err := VerifyPKCE(v, v); err == nil {
		t.Fatal("plain challenge accepted")
	}
}

func TestParseAuthorize(t *testing.T) {
	good := url.Values{"response_type": {"code"}, "client_id": {"spa"}, "redirect_uri": {"https://app.example.org/cb"}, "state": {"xyz"}, "code_challenge": {Challenge(strings.Repeat("v", 50))}, "code_challenge_method": {"S256"}}
	if _, err := ParseAuthorize(good); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"response_type": "token", "state": "", "code_challenge_method": "plain", "code_challenge": "short", "redirect_uri": "/relative", "client_id": ""} {
		q := url.Values{}
		for kk, vv := range good {
			q[kk] = vv
		}
		q.Set(k, v)
		if _, err := ParseAuthorize(q); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
}

func TestCodeFlow(t *testing.T) {
	svc, _, ring := setup(t)
	ctx := context.Background()
	verifier := strings.Repeat("v", 64)
	req := AuthorizeRequest{ResponseType: "code", ClientID: "spa", RedirectURI: "https://app.example.org/cb", State: "st", CodeChallenge: Challenge(verifier), CodeChallengeMethod: "S256"}
	c, err := svc.ValidateClient(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	bad := req
	bad.RedirectURI = "https://app.example.org/cb/../evil"
	if _, err := svc.ValidateClient(ctx, bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("unregistered redirect accepted")
	}
	bad.ClientID = "nope"
	if _, err := svc.ValidateClient(ctx, bad); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("unknown client accepted")
	}
	actor := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tA, SessionID: "s1", Roles: []string{"member"}, AMR: []string{"pwd"}}
	if _, err := svc.IssueCode(ctx, tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u9", TenantID: tB, SessionID: "s9"}, c, req); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("client of another tenant accepted")
	}
	code, err := svc.IssueCode(ctx, actor, c, req)
	if err != nil || code == "" {
		t.Fatal(code, err)
	}
	// Wrong verifier burns the code.
	if _, err := svc.Redeem(ctx, TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: req.RedirectURI, ClientID: "spa", CodeVerifier: strings.Repeat("w", 64)}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("wrong verifier: %v", err)
	}
	if _, err := svc.Redeem(ctx, TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: req.RedirectURI, ClientID: "spa", CodeVerifier: verifier}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatal("burnt code redeemed")
	}
	code, _ = svc.IssueCode(ctx, actor, c, req)
	for name, r := range map[string]TokenRequest{
		"redirect mismatch": {GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example.org/other", ClientID: "spa", CodeVerifier: verifier},
		"client mismatch":   {GrantType: "authorization_code", Code: code, RedirectURI: req.RedirectURI, ClientID: "backend", CodeVerifier: verifier},
	} {
		code, _ = svc.IssueCode(ctx, actor, c, req)
		r.Code = code
		if _, err := svc.Redeem(ctx, r); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := svc.Redeem(ctx, TokenRequest{GrantType: "password", Code: "x", RedirectURI: "y", ClientID: "z"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("other grant accepted")
	}
	code, _ = svc.IssueCode(ctx, actor, c, req)
	resp, err := svc.Redeem(ctx, TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: req.RedirectURI, ClientID: "spa", CodeVerifier: verifier})
	if err != nil || resp.TokenType != "Bearer" || resp.ExpiresIn <= 0 {
		t.Fatal(resp, err)
	}
	keys, _ := authclient.ParseJWKS(ring.JWKSJSON())
	v := authclient.New(authclient.Config{Issuer: "https://auth.example.org", Audience: "spa"}, authclient.StaticKeys(keys), nil)
	_ = v.RefreshKeys(ctx)
	id, err := v.Verify(ctx, resp.AccessToken)
	if err != nil || id.UserID != "u1" || id.Audience != "spa" || id.SessionID != "s1" {
		t.Fatalf("%+v %v", id, err)
	}
	// Confidential client needs its secret.
	creq := AuthorizeRequest{ResponseType: "code", ClientID: "backend", RedirectURI: "https://svc.example.org/cb", State: "st", CodeChallenge: Challenge(verifier), CodeChallengeMethod: "S256"}
	cc, _ := svc.ValidateClient(ctx, creq)
	code, _ = svc.IssueCode(ctx, actor, cc, creq)
	if _, err := svc.Redeem(ctx, TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: creq.RedirectURI, ClientID: "backend", CodeVerifier: verifier}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("missing secret: %v", err)
	}
	code, _ = svc.IssueCode(ctx, actor, cc, creq)
	if _, err := svc.Redeem(ctx, TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: creq.RedirectURI, ClientID: "backend", CodeVerifier: verifier, ClientSecret: "wrong"}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("wrong secret: %v", err)
	}
	code, _ = svc.IssueCode(ctx, actor, cc, creq)
	if _, err := svc.Redeem(ctx, TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: creq.RedirectURI, ClientID: "backend", CodeVerifier: verifier, ClientSecret: "s3cret-value-for-confidential"}); err != nil {
		t.Fatal(err)
	}
}
