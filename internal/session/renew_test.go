package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
)

// Renew rotates the secret and moves the absolute expiry; the old secret
// keeps resolving for RenewGrace, then never again, while the session lives
// on under the new one.
func TestRenewRotatesAndExtends(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, secret, err := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Roles: []string{"admin"}, AMR: []string{"pwd"}, Policy: h.policy()})
	if err != nil {
		t.Fatal(err)
	}
	// An active user (a request every 20 min) until 30 min are left of the
	// 2 h lifetime; the idle timeout is 30 min.
	for i := 0; i < 4; i++ {
		h.now = h.now.Add(22*time.Minute + 30*time.Second)
		if _, err := h.m.Resolve(ctx, secret); err != nil {
			t.Fatal(err)
		}
	}
	ren, err := h.m.Renew(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if ren.Secret == "" || ren.Secret == secret || ren.SessionID != s.ID {
		t.Fatalf("renewal %+v", ren)
	}
	if !ren.ExpiresAt.Equal(h.now.Add(2*time.Hour)) || ren.Idle != 30*time.Minute {
		t.Fatalf("expiry %v idle %v", ren.ExpiresAt, ren.Idle)
	}
	row := h.st.sessions[s.ID]
	if string(row.SecretHash) != crypto.HashToken(ren.Secret) || !row.ExpiresAt.Equal(ren.ExpiresAt) {
		t.Fatal("the row carries the new secret hash and expiry")
	}
	// Both secrets resolve to the same session within the grace.
	for _, sec := range []string{secret, ren.Secret} {
		if a, err := h.m.Resolve(ctx, sec); err != nil || a.SessionID != s.ID {
			t.Fatalf("resolve within grace: %+v %v", a, err)
		}
	}
	// Past the grace the old secret is refused; the session is not revoked.
	h.now = h.now.Add(RenewGrace + time.Second)
	if _, err := h.m.Resolve(ctx, secret); !errors.Is(err, ErrNoSession) {
		t.Fatal("a replaced secret must stop resolving after the grace")
	}
	if _, err := h.m.Resolve(ctx, ren.Secret); err != nil {
		t.Fatal("the session lives on under the new secret")
	}
	if h.st.sessions[s.ID].RevokedAt != nil {
		t.Fatal("rotation must not revoke the session")
	}
	// Past the original 2 h lifetime the renewed session is still alive.
	for i := 0; i < 2; i++ {
		h.now = h.now.Add(20 * time.Minute)
		if _, err := h.m.Resolve(ctx, ren.Secret); err != nil {
			t.Fatalf("renewed session past its original expiry: %v", err)
		}
	}
	if !h.now.After(s.CreatedAt.Add(2 * time.Hour)) {
		t.Fatal("the check must run past the original lifetime")
	}
}

// A second refresh moments later (another tab) only touches; a refresh with
// a secret already replaced never rotates again.
func TestRenewThrottlesAndIgnoresReplacedSecrets(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, secret, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	h.now = h.now.Add(10 * time.Minute)
	first, err := h.m.Renew(ctx, secret)
	if err != nil || first.Secret == "" {
		t.Fatal(err)
	}
	h.now = h.now.Add(10 * time.Second)
	again, err := h.m.Renew(ctx, first.Secret)
	if err != nil || again.Secret != "" || !again.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("within RenewMinInterval: %+v %v", again, err)
	}
	stale, err := h.m.Renew(ctx, secret) // the replaced secret, still in its grace
	if err != nil || stale.Secret != "" {
		t.Fatalf("a replaced secret must not rotate: %+v %v", stale, err)
	}
	if string(h.st.sessions[s.ID].SecretHash) != crypto.HashToken(first.Secret) {
		t.Fatal("the current secret is unchanged")
	}
	// After the interval the current secret rotates again.
	h.now = h.now.Add(RenewMinInterval)
	next, err := h.m.Renew(ctx, first.Secret)
	if err != nil || next.Secret == "" || next.Secret == first.Secret {
		t.Fatalf("%+v %v", next, err)
	}
}

// Renewal never revives an ended session: idle-expired, revoked or unknown.
func TestRenewRefusesEndedSessions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, idle, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	h.now = h.now.Add(31 * time.Minute)
	if _, err := h.m.Renew(ctx, idle); !errors.Is(err, ErrNoSession) {
		t.Fatal("an idle-expired session must not renew")
	}
	s, revoked, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	if err := h.m.Revoke(ctx, tid, s.ID, ReasonSignout); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.Renew(ctx, revoked); !errors.Is(err, ErrNoSession) {
		t.Fatal("a revoked session must not renew")
	}
	if _, err := h.m.Renew(ctx, "nope"); !errors.Is(err, ErrNoSession) {
		t.Fatal("an unknown secret must not renew")
	}
}

// A store failure surfaces and leaves the session as it was.
func TestRenewStoreFailure(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	fs := &failStore{fakeStore: h.st, fail: map[string]bool{}}
	h.m.st = fs
	s, secret, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	fs.fail["renew"] = true
	if _, err := h.m.Renew(ctx, secret); err == nil {
		t.Fatal("renew failure must surface")
	}
	if string(h.st.sessions[s.ID].SecretHash) != crypto.HashToken(secret) {
		t.Fatal("a failed renewal keeps the secret")
	}
	if _, err := h.m.Resolve(ctx, secret); err != nil {
		t.Fatal("the session still resolves")
	}
}

type noEntropy struct{}

func (noEntropy) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

// Every lookup Renew makes after Resolve can fail (a race with revocation,
// a tenant change, an outage); none of them rotates the secret.
func TestRenewFailurePaths(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	fs := &failStore{fakeStore: h.st, fail: map[string]bool{}}
	h.m.st = fs
	s, secret, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	unchanged := func(what string) {
		t.Helper()
		if string(h.st.sessions[s.ID].SecretHash) != crypto.HashToken(secret) {
			t.Fatalf("%s: the secret must not rotate", what)
		}
	}
	fs.fail["get"] = true
	if _, err := h.m.Renew(ctx, secret); !errors.Is(err, ErrNoSession) {
		t.Fatalf("session lookup failure: %v", err)
	}
	unchanged("get")
	fs.fail["get"] = false
	fs.fail["tenant"] = true
	if _, err := h.m.Renew(ctx, secret); !errors.Is(err, ErrNoSession) {
		t.Fatalf("tenant lookup failure: %v", err)
	}
	unchanged("tenant")
	fs.fail["tenant"] = false
	good := h.st.tenants[tid]
	bad := good
	bad.Policy = []byte(`{"session_lifetime":"not a duration"}`)
	h.st.tenants[tid] = bad
	if _, err := h.m.Renew(ctx, secret); err == nil {
		t.Fatal("an unreadable tenant policy must fail")
	}
	unchanged("policy")
	h.st.tenants[tid] = good
	restore := crypto.SetRand(noEntropy{})
	_, err := h.m.Renew(ctx, secret)
	restore()
	if err == nil {
		t.Fatal("no entropy must fail")
	}
	unchanged("entropy")
}

// Without a cached view (the cache was flushed) Renew rebuilds it from the
// database and still rotates.
func TestRenewWithoutCachedView(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, secret, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Roles: []string{"admin"}, Policy: h.policy()})
	h.m.cache = nil
	ren, err := h.m.Renew(ctx, secret)
	if err != nil || ren.Secret == "" || ren.SessionID != s.ID || ren.Idle != 30*time.Minute {
		t.Fatalf("%+v %v", ren, err)
	}
	if a, err := h.m.Resolve(ctx, ren.Secret); err != nil || a.SessionID != s.ID {
		t.Fatalf("%+v %v", a, err)
	}
}
