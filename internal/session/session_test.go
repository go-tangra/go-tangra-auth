package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

const tid = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

type harness struct {
	m   *Manager
	st  *fakeStore
	mem *cache.Memory
	now time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{now: time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return h.now }
	h.st = newFake(clock)
	h.st.tenants[tid] = store.Tenant{ID: tid, Status: "active", Kind: "customer", Policy: []byte(`{"session_lifetime":"2h","idle_timeout":"30m"}`)}
	h.st.roles[tid+"/u1"] = []string{"admin"}
	h.mem = cache.NewMemory()
	h.m = New(h.st, cache.New(h.mem), nil)
	h.m.now = clock
	return h
}

func (h *harness) policy() tenant.Policy {
	p, _ := tenant.ParsePolicy(h.st.tenants[tid].Policy, false)
	return p
}

func TestCreateResolveTouchExpire(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, secret, err := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Roles: []string{"admin"}, AMR: []string{"pwd"}, IPHash: "ip", UserAgent: "ua", Policy: h.policy()})
	if err != nil {
		t.Fatal(err)
	}
	if string(s.SecretHash) == secret || string(s.SecretHash) != crypto.HashToken(secret) {
		t.Fatal("cookie value must be stored hashed")
	}
	if s.ExpiresAt.Sub(s.CreatedAt) != 2*time.Hour {
		t.Fatal("absolute lifetime from policy")
	}
	a, err := h.m.Resolve(ctx, secret)
	if err != nil || a.Kind != tenantctx.KindUser || a.UserID != "u1" || a.TenantID != tid || a.SessionID != s.ID || a.Roles[0] != "admin" {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err := h.m.Resolve(ctx, "nope"); !errors.Is(err, ErrNoSession) {
		t.Fatal("unknown secret")
	}
	if _, err := h.m.Resolve(ctx, ""); !errors.Is(err, ErrNoSession) {
		t.Fatal("empty secret")
	}
	// Touch extends the idle window (once per minute), from cache and from DB.
	h.now = h.now.Add(25 * time.Minute)
	if _, err := h.m.Resolve(ctx, secret); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(25 * time.Minute)
	if _, err := h.m.Resolve(ctx, secret); err != nil {
		t.Fatal("touch must have extended idle")
	}
	// Cache miss falls back to the database and the tenant policy.
	_ = h.mem.Del(ctx, cache.SessionKey(crypto.HashToken(secret)))
	if _, err := h.m.Resolve(ctx, secret); err != nil {
		t.Fatal(err)
	}
	// Idle timeout ends the session and publishes a revocation.
	h.now = h.now.Add(31 * time.Minute)
	if _, err := h.m.Resolve(ctx, secret); !errors.Is(err, ErrNoSession) {
		t.Fatal("idle session resolved")
	}
	if got := h.st.sessions[s.ID]; got.RevokedAt == nil || *got.RevokedReason != ReasonIdle {
		t.Fatalf("idle revocation not recorded: %+v", got)
	}
	// Absolute expiry.
	s2, secret2, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	h.now = s2.ExpiresAt.Add(time.Second)
	if _, err := h.m.Resolve(ctx, secret2); !errors.Is(err, ErrNoSession) {
		t.Fatal("expired session resolved")
	}
	// Suspended tenant blocks resolution on the DB path.
	h.now = time.Date(2026, 9, 16, 20, 0, 0, 0, time.UTC)
	_, secret3, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	_ = h.mem.Del(ctx, cache.SessionKey(crypto.HashToken(secret3)))
	tn := h.st.tenants[tid]
	tn.Status = "suspended"
	h.st.tenants[tid] = tn
	if _, err := h.m.Resolve(ctx, secret3); !errors.Is(err, ErrNoSession) {
		t.Fatal("suspended tenant session resolved")
	}
}

func TestRevocationFanOut(t *testing.T) {
	h := newHarness(t)
	ctx := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tid})
	got := make(chan string, 16)
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = h.mem.Subscribe(subCtx, cache.RevokedChannel, func(s string) { got <- s }) }()
	time.Sleep(10 * time.Millisecond)
	s1, sec1, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	s2, sec2, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	_, sec3, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u2", Policy: h.policy()})
	// Sign-out of one session.
	if err := h.m.Revoke(ctx, tid, s1.ID, ReasonSignout); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Resolve(ctx, sec1); !errors.Is(err, ErrNoSession) {
		t.Fatal("revoked session resolved")
	}
	if _, err := h.m.Resolve(ctx, sec2); err != nil {
		t.Fatal("sibling session affected")
	}
	if err := h.m.Revoke(ctx, "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66", s2.ID, ReasonSignout); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("foreign tenant revoke must not find the session")
	}
	// User-wide revocation keeps one session.
	s4, sec4, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	if err := h.m.RevokeUser(ctx, tid, "u1", ReasonPassword, s4.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Resolve(ctx, sec2); !errors.Is(err, ErrNoSession) {
		t.Fatal("s2 must be revoked")
	}
	if _, err := h.m.Resolve(ctx, sec4); err != nil {
		t.Fatal("kept session must survive")
	}
	// User-wide without keep uses a user mark that applies to sessions created before it.
	h.now = h.now.Add(time.Second)
	if err := h.m.RevokeUser(ctx, tid, "u1", ReasonDeactivated, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Resolve(ctx, sec4); !errors.Is(err, ErrNoSession) {
		t.Fatal("user mark must revoke")
	}
	h.now = h.now.Add(time.Second)
	_, sec5, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	if _, err := h.m.Resolve(ctx, sec5); err != nil {
		t.Fatal("sessions created after the mark are fine")
	}
	// Tenant-wide revocation.
	h.now = h.now.Add(time.Second)
	if err := h.m.RevokeTenant(ctx, tid, ReasonSuspended); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Resolve(ctx, sec3); !errors.Is(err, ErrNoSession) {
		t.Fatal("tenant mark must revoke u2")
	}
	// Feed: every revocation is listed after a cursor and marks were published.
	revs, err := h.m.Since(ctx, time.Time{}, 100)
	if err != nil || len(revs) < 5 {
		t.Fatalf("feed %d %v", len(revs), err)
	}
	kinds := map[string]int{}
	for _, r := range revs {
		kinds[r.Kind]++
	}
	if kinds["session"] < 2 || kinds["user"] != 1 || kinds["tenant"] != 1 {
		t.Fatalf("kinds %v", kinds)
	}
	if later, _ := h.m.Since(ctx, revs[len(revs)-1].TS, 100); len(later) != 0 {
		t.Fatal("cursor")
	}
	if len(got) < 5 {
		t.Fatalf("pub/sub fan-out: %d messages", len(got))
	}
	// Listing shows only live sessions and marks the current one.
	_, _, _ = h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", UserAgent: "ua-live", Policy: h.policy()})
	views, err := h.m.ListMine(ctx, tid, "u1", "")
	if err != nil || len(views) != 1 || views[0].UserAgent != "ua-live" {
		t.Fatalf("%v %v", views, err)
	}
	views, _ = h.m.ListMine(ctx, tid, "u1", views[0].ID)
	if !views[0].Current {
		t.Fatal("current flag")
	}
}
