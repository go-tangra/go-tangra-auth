package grpcapi

import (
	"bytes"
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenant"
	"github.com/go-freya/freya/services/auth/internal/token"
)

const tid = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

type stream struct {
	grpc.ServerStream
	ctx context.Context
	got []*authv1.Revocation
}

func (s *stream) Context() context.Context        { return s.ctx }
func (s *stream) Send(r *authv1.Revocation) error { s.got = append(s.got, r); return nil }

func TestKeysFeedAndIntrospect(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tid, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	c := cache.New(cache.NewMemory())
	sm := session.New(ms, c, nil)
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{2}, 32))
	ring := token.NewRing(token.NewMemKeys(), env, token.Config{})
	if err := ring.Load(ctx); err != nil {
		t.Fatal(err)
	}
	iss := token.NewIssuer(ring, "https://auth.example.org")
	ks := &KeysServer{Ring: ring, NotAfterGrace: func() (int64, int64) { return 900, 60 }}
	resp, err := ks.List(ctx, &authv1.ListKeysRequest{})
	if err != nil || len(resp.Keys) != 1 || resp.Keys[0].Kty != "OKP" || len(resp.Keys[0].PublicKey) != 32 || resp.Keys[0].State != "active" {
		t.Fatalf("%v %v", resp, err)
	}
	ss := &SessionsServer{Sessions: sm, Tokens: iss, Poll: 5 * time.Millisecond}
	// Empty feed with an initial cursor.
	feed, err := ss.RevokedSince(ctx, &authv1.RevokedSinceRequest{})
	if err != nil || len(feed.Revocations) != 0 || feed.NextCursor == "" {
		t.Fatalf("%v %v", feed, err)
	}
	if _, err := ss.RevokedSince(ctx, &authv1.RevokedSinceRequest{Cursor: "abc"}); err == nil {
		t.Fatal("bad cursor accepted")
	}
	// A session, a token, then sign-out: introspection flips to revoked and the feed carries it.
	pol := tenant.DefaultPolicy()
	sess, _, _ := sm.Create(ctx, session.CreateParams{TenantID: tid, UserID: "u1", Roles: []string{"admin"}, AMR: []string{"pwd"}, Policy: pol})
	tok, _, _ := iss.Issue(token.Request{UserID: "u1", TenantID: tid, SessionID: sess.ID, Roles: []string{"admin"}})
	in, err := ss.Introspect(ctx, &authv1.IntrospectRequest{Token: tok})
	if err != nil || !in.Active || in.UserId != "u1" || in.SessionId != sess.ID || in.Roles[0] != "admin" {
		t.Fatalf("%v %v", in, err)
	}
	if in, _ := ss.Introspect(ctx, &authv1.IntrospectRequest{Token: "garbage"}); in.Active || in.Reason != "invalid" {
		t.Fatalf("%v", in)
	}
	time.Sleep(1100 * time.Millisecond) // revocation ts must be ≥ iat at second granularity
	if err := sm.Revoke(ctx, tid, sess.ID, session.ReasonSignout); err != nil {
		t.Fatal(err)
	}
	if in, _ := ss.Introspect(ctx, &authv1.IntrospectRequest{Token: tok}); in.Active || in.Reason != "revoked" {
		t.Fatalf("%v", in)
	}
	feed, _ = ss.RevokedSince(ctx, &authv1.RevokedSinceRequest{Cursor: feed.NextCursor})
	if len(feed.Revocations) != 1 || feed.Revocations[0].Kind != "session" || feed.Revocations[0].SubjectId != sess.ID {
		t.Fatalf("%v", feed)
	}
	again, _ := ss.RevokedSince(ctx, &authv1.RevokedSinceRequest{Cursor: feed.NextCursor})
	if len(again.Revocations) != 0 {
		t.Fatal("cursor must advance")
	}
	// Watch streams existing entries then stops with the context.
	wctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	st := &stream{ctx: wctx}
	if err := ss.Watch(&authv1.WatchRequest{}, st); err != nil || len(st.got) != 1 {
		t.Fatalf("%v %d", err, len(st.got))
	}
}
