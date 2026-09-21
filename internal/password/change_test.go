package password

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/email"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenant"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

const tid = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

type nullSender struct{}

func (nullSender) Send(context.Context, email.Message) error { return nil }

func setup(t *testing.T) (*memstore.Store, *session.Manager, *email.Outbox) {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tid, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte(`{"password_min_length":10}`)})
	h, _ := Hash("old-password-1")
	ms.AddUser(store.User{ID: "u1", TenantID: tid, Email: "alice@x.test", Status: "active", PasswordHash: &h})
	sm := session.New(ms, cache.New(cache.NewMemory()), nil)
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{2}, 32))
	return ms, sm, email.NewOutbox(env, nullSender{}, nil, 3, nil)
}

func TestChange(t *testing.T) {
	ms, sm, _ := setup(t)
	ctx := context.Background()
	pol := tenant.DefaultPolicy()
	s1, sec1, _ := sm.Create(ctx, session.CreateParams{TenantID: tid, UserID: "u1", Policy: pol})
	_, sec2, _ := sm.Create(ctx, session.CreateParams{TenantID: tid, UserID: "u1", Policy: pol})
	actor := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tid, SessionID: s1.ID}
	ch := NewChanger(ms, sm, nil)
	ch.SetPad(func(time.Time) {})
	if err := ch.Change(ctx, actor, "wrong", "new-password-long"); !errors.Is(err, ErrCurrent) {
		t.Fatalf("wrong current: %v", err)
	}
	if err := ch.Change(ctx, actor, "old-password-1", "short"); !errors.Is(err, ErrTooShort) {
		t.Fatalf("policy: %v", err)
	}
	if err := ch.Change(ctx, actor, "old-password-1", "new-password-long"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Verify("new-password-long", *ms.Users[tid+"/alice@x.test"].PasswordHash); !ok {
		t.Fatal("new hash not stored")
	}
	if _, err := sm.Resolve(ctx, sec1); err != nil {
		t.Fatal("current session must survive")
	}
	if _, err := sm.Resolve(ctx, sec2); !errors.Is(err, session.ErrNoSession) {
		t.Fatal("other session must end")
	}
}

func TestRecovery(t *testing.T) {
	ms, sm, ob := setup(t)
	ctx := context.Background()
	rec := NewRecovery(ms, ob, sm, nil, "https://auth.example.org")
	rec.SetPad(func(time.Time) {})
	// Unknown tenant/email: no error, nothing queued.
	for _, c := range [][2]string{{"nope", "alice@x.test"}, {"acme", "ghost@x.test"}, {"Bad Slug", "alice@x.test"}} {
		if err := rec.Request(ctx, c[0], c[1], "ip"); err != nil || len(ms.Outbox) != 0 {
			t.Fatalf("%v → %v outbox=%d", c, err, len(ms.Outbox))
		}
	}
	_, sec, _ := sm.Create(ctx, session.CreateParams{TenantID: tid, UserID: "u1", Policy: tenant.DefaultPolicy()})
	if err := rec.Request(ctx, "acme", " Alice@X.test ", "ip"); err != nil || len(ms.Outbox) != 1 || len(ms.Recoveries) != 1 {
		t.Fatal(err, len(ms.Outbox))
	}
	p, _ := ob.Decode("alice@x.test", ms.Outbox[0].PayloadEnc)
	tok := strings.TrimSpace(strings.Split(p.Text[strings.Index(p.Text, "token=")+6:], "\n")[0])
	for _, r := range ms.Recoveries {
		if r.TokenHash == tok || r.TokenHash != crypto.HashToken(tok) || time.Until(r.ExpiresAt) > RecoveryLifetime+time.Minute {
			t.Fatal("token must be stored hashed with a 30 min expiry")
		}
	}
	if err := rec.Complete(ctx, tok, "short"); !errors.Is(err, ErrTooShort) {
		t.Fatalf("policy before consumption: %v", err)
	}
	if err := rec.Complete(ctx, tok, "brand-new-password"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Verify("brand-new-password", *ms.Users[tid+"/alice@x.test"].PasswordHash); !ok {
		t.Fatal("password not set")
	}
	if _, err := sm.Resolve(ctx, sec); !errors.Is(err, session.ErrNoSession) {
		t.Fatal("all sessions must end on recovery")
	}
	if err := rec.Complete(ctx, tok, "brand-new-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("token reused")
	}
	if err := rec.Complete(ctx, "", "brand-new-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("empty token")
	}
	// Expired tokens are refused.
	if err := rec.Request(ctx, "acme", "alice@x.test", "ip"); err != nil {
		t.Fatal(err)
	}
	p, _ = ob.Decode("alice@x.test", ms.Outbox[1].PayloadEnc)
	tok2 := strings.TrimSpace(strings.Split(p.Text[strings.Index(p.Text, "token=")+6:], "\n")[0])
	ms.Now = func() time.Time { return time.Now().Add(RecoveryLifetime + time.Minute) }
	if err := rec.Complete(ctx, tok2, "brand-new-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("expired token accepted")
	}
}
