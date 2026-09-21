package grpcapi

import (
	"bytes"
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenant"
	"github.com/go-freya/freya/services/auth/internal/token"
)

func TestExchangeAndMintToken(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tid, Slug: "platform", Status: "active", Kind: "platform", Policy: []byte("{}")})
	c := cache.New(cache.NewMemory())
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	sm := session.New(ms, c, aw)
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{3}, 32))
	ring := token.NewRing(token.NewMemKeys(), env, token.Config{})
	if err := ring.Load(ctx); err != nil {
		t.Fatal(err)
	}
	iss := token.NewIssuer(ring, "https://auth.example.org")
	ss := &SessionsServer{Sessions: sm, Tokens: iss, Audit: aw}

	// No session → Unauthenticated (never a token).
	if _, err := ss.Exchange(ctx, &authv1.ExchangeRequest{CookieSecret: "nope"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("garbage cookie: %v", err)
	}
	if _, err := ss.MintToken(ctx, &authv1.MintTokenRequest{TenantId: tid, SessionId: "ghost"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("ghost session: %v", err)
	}
	sess, secret, err := sm.Create(ctx, session.CreateParams{TenantID: tid, UserID: "u1", Roles: []string{"operator"}, AMR: []string{"pwd", "otp"}, Operator: true, Policy: tenant.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	ex, err := ss.Exchange(ctx, &authv1.ExchangeRequest{CookieSecret: secret, Audience: "gateway"})
	if err != nil || ex.Identity.UserId != "u1" || ex.Identity.SessionId != sess.ID || !ex.Identity.Operator || ex.Identity.Roles[0] != "operator" || len(ex.Identity.Amr) != 2 || ex.AccessToken == "" {
		t.Fatalf("%v %v", ex, err)
	}
	claims, err := iss.Verify(ex.AccessToken)
	if err != nil || claims.SessionID != sess.ID || claims.TenantID != tid || claims.Audience[0] != "gateway" || !claims.ExpiresAt.Time.Equal(ex.ExpiresAt.AsTime()) {
		t.Fatalf("%+v %v", claims, err)
	}
	mt, err := ss.MintToken(ctx, &authv1.MintTokenRequest{TenantId: tid, SessionId: sess.ID})
	if err != nil || mt.AccessToken == "" || mt.Identity.SessionId != sess.ID {
		t.Fatalf("%v %v", mt, err)
	}
	if c, err := iss.Verify(mt.AccessToken); err != nil || len(c.Audience) != 0 {
		t.Fatalf("audience must be absent when not requested: %+v %v", c, err)
	}
	// Wrong tenant for the session id → refused.
	if _, err := ss.MintToken(ctx, &authv1.MintTokenRequest{TenantId: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99", SessionId: sess.ID}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("foreign tenant: %v", err)
	}
	// After sign-out both paths refuse.
	if err := sm.Revoke(ctx, tid, sess.ID, session.ReasonSignout); err != nil {
		t.Fatal(err)
	}
	if _, err := ss.Exchange(ctx, &authv1.ExchangeRequest{CookieSecret: secret}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked cookie: %v", err)
	}
	if _, err := ss.MintToken(ctx, &authv1.MintTokenRequest{TenantId: tid, SessionId: sess.ID}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked session: %v", err)
	}
	aw.Close()
	var ok, refused int
	for _, r := range ms.AuditRows {
		if r.EventType == string(audit.TokenExchanged) {
			switch r.Outcome {
			case "ok":
				ok++
			case "refused":
				refused++
			}
		}
	}
	if ok != 2 || refused < 4 {
		t.Fatalf("audit ok=%d refused=%d", ok, refused)
	}
	// Expired session: ByID refuses.
	old, _, _ := sm.Create(ctx, session.CreateParams{TenantID: tid, UserID: "u1", Policy: tenant.DefaultPolicy()})
	s2 := ms.Sessions[old.ID]
	s2.ExpiresAt = time.Now().Add(-time.Minute)
	if _, err := sm.ByID(ctx, tid, old.ID); err == nil {
		t.Fatal("expired session resolved by id")
	}
}
