package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/store"
)

// TestViewRefreshOnPolicyVersion: a cached session view reloads its effective
// roles when the tenant's policy version moves (group or role change) and
// otherwise serves from the cache without touching the database.
func TestViewRefreshOnPolicyVersion(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	avatar := "ab12"
	h.st.users[tid+"/u1"] = store.User{ID: "u1", TenantID: tid, Email: "dana@x.test", DisplayName: "Dana Kovač", AvatarID: &avatar}
	_, secret, err := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Roles: []string{"admin"}, AMR: []string{"pwd"}, Policy: h.policy()})
	if err != nil {
		t.Fatal(err)
	}
	a, err := h.m.Resolve(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if a.DisplayName != "Dana Kovač" || a.AvatarURL != "/api/v1/users/u1/avatar/ab12" {
		t.Fatalf("actor must carry the profile: %+v", a)
	}
	hits := h.st.roleHits
	if _, err := h.m.Resolve(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if h.st.roleHits != hits {
		t.Fatalf("unchanged version must not reload roles (%d → %d)", hits, h.st.roleHits)
	}
	// A group/role change bumps the tenant version; the next resolve reloads.
	h.st.roles[tid+"/u1"] = []string{"admin", "invoices-reader"}
	if _, err := h.m.cache.BumpTenantVersion(ctx, tid); err != nil {
		t.Fatal(err)
	}
	a, err = h.m.Resolve(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Roles) != 2 || a.Roles[1] != "invoices-reader" {
		t.Fatalf("roles must be refreshed after a version bump: %v", a.Roles)
	}
	if h.st.roleHits != hits+1 {
		t.Fatalf("exactly one reload expected, got %d", h.st.roleHits-hits)
	}
	// The refreshed view is cached again: no further reload.
	if _, err := h.m.Resolve(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if h.st.roleHits != hits+1 {
		t.Fatalf("refreshed view must be cached, got %d reloads", h.st.roleHits-hits)
	}
	// ByID (token minting) sees the same effective roles and profile.
	b, err := h.m.ByID(ctx, tid, a.SessionID)
	if err != nil || len(b.Roles) != 2 || b.DisplayName != "Dana Kovač" {
		t.Fatalf("%+v %v", b, err)
	}
	// A profile change evicts the actor's own view so the next resolve reloads it.
	h.st.users[tid+"/u1"] = store.User{ID: "u1", TenantID: tid, Email: "dana@x.test", DisplayName: "D. Kovač"}
	h.m.RefreshUser(ctx, tid, "u1")
	a, _ = h.m.Resolve(ctx, secret)
	if a.DisplayName != "D. Kovač" || a.AvatarURL != "" {
		t.Fatalf("profile must be reloaded after RefreshUser: %+v", a)
	}
}

// Failure branches of the refresh paths: a store error keeps the cached view,
// a listing error skips eviction, and ByID surfaces policy/role errors.
func TestRefreshFailureBranches(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	fs := &failStore{fakeStore: h.st, fail: map[string]bool{}}
	h.m.st = fs
	_, secret, err := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Roles: []string{"admin"}, Policy: h.policy()})
	if err != nil {
		t.Fatal(err)
	}
	// Version moved but roles cannot be loaded: the cached roles stay (fail soft on read, the next resolve retries).
	_, _ = h.m.cache.BumpTenantVersion(ctx, tid)
	fs.fail["roles"] = true
	a, err := h.m.Resolve(ctx, secret)
	if err != nil || len(a.Roles) != 1 || a.Roles[0] != "admin" {
		t.Fatalf("%+v %v", a, err)
	}
	fs.fail["roles"] = false
	if a, _ = h.m.Resolve(ctx, secret); len(a.Roles) != 1 {
		t.Fatalf("retry after the store recovers: %+v", a)
	}
	// RefreshUser: listing fails → nothing evicted, no panic; nil cache → no-op.
	fs.fail["listUser"] = true
	h.m.RefreshUser(ctx, tid, "u1")
	fs.fail["listUser"] = false
	noCache := New(h.st, nil, nil)
	noCache.RefreshUser(ctx, tid, "u1")
	if noCache.tenantVersion(ctx, tid) != 0 {
		t.Fatal("no cache → version 0")
	}
	// ByID: a role load failure is an error; a missing user row leaves the profile empty.
	fs.fail["roles"] = true
	if _, err := h.m.ByID(ctx, tid, a.SessionID); err == nil {
		t.Fatal("ByID must surface a roles error")
	}
	fs.fail["roles"] = false
	fs.fail["user"] = true
	b, err := h.m.ByID(ctx, tid, a.SessionID)
	if err != nil || b.DisplayName != "" {
		t.Fatalf("missing user row must not fail the session: %+v %v", b, err)
	}
	if _, err := h.m.ByID(ctx, tid, "nope"); err == nil {
		t.Fatal("unknown session id")
	}
	// Liveness: an expired session and a revoked one are refused by ByID.
	h.now = h.now.Add(3 * time.Hour)
	if _, err := h.m.ByID(ctx, tid, a.SessionID); !errors.Is(err, ErrNoSession) {
		t.Fatalf("expired: %v", err)
	}
	h.now = h.now.Add(-3 * time.Hour)
	if err := h.m.Revoke(ctx, tid, a.SessionID, ReasonSignout); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.ByID(ctx, tid, a.SessionID); !errors.Is(err, ErrNoSession) {
		t.Fatalf("revoked: %v", err)
	}
	_, secret2, _ := h.m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: h.policy()})
	a2, _ := h.m.Resolve(ctx, secret2)
	a.SessionID = a2.SessionID
	if _, err := h.m.ByID(ctx, "", a.SessionID); err == nil {
		t.Fatal("empty tenant")
	}
	fs.fail["user"] = false
	fs.fail["tenant"] = true
	if _, err := h.m.ByID(ctx, tid, a.SessionID); !errors.Is(err, ErrNoSession) {
		t.Fatalf("tenant unavailable: %v", err)
	}
	fs.fail["tenant"] = false
	h.st.tenants[tid] = store.Tenant{ID: tid, Status: "active", Kind: "customer", Policy: []byte(`{"session_lifetime":"bad"}`)}
	if _, err := h.m.ByID(ctx, tid, a.SessionID); err == nil {
		t.Fatal("ByID must surface a policy parse error")
	}
}
