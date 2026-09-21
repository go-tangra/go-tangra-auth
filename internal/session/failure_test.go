package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenant"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

var errDown = errors.New("down")

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, errDown }

// failStore fails the named operations.
type failStore struct {
	*fakeStore
	fail map[string]bool
}

func (f *failStore) on(op string) bool { return f.fail[op] }
func (f *failStore) Insert(ctx context.Context, s store.Session) error {
	if f.on("insert") {
		return errDown
	}
	return f.fakeStore.Insert(ctx, s)
}
func (f *failStore) Tenant(ctx context.Context, tid string) (store.Tenant, error) {
	if f.on("tenant") {
		return store.Tenant{}, errDown
	}
	return f.fakeStore.Tenant(ctx, tid)
}
func (f *failStore) Roles(ctx context.Context, tid, uid string) ([]string, error) {
	if f.on("roles") {
		return nil, errDown
	}
	return f.fakeStore.Roles(ctx, tid, uid)
}
func (f *failStore) Touch(ctx context.Context, tid, id string) error {
	if f.on("touch") {
		return errDown
	}
	return f.fakeStore.Touch(ctx, tid, id)
}
func (f *failStore) Revoke(ctx context.Context, tid, id, reason string) error {
	if f.on("revoke") {
		return errDown
	}
	return f.fakeStore.Revoke(ctx, tid, id, reason)
}
func (f *failStore) RevokeUser(ctx context.Context, tid, uid, reason, keep string) error {
	if f.on("revokeUser") {
		return errDown
	}
	return f.fakeStore.RevokeUser(ctx, tid, uid, reason, keep)
}
func (f *failStore) RevokeTenant(ctx context.Context, tid, reason string) error {
	if f.on("revokeTenant") {
		return errDown
	}
	return f.fakeStore.RevokeTenant(ctx, tid, reason)
}
func (f *failStore) InsertRevocation(ctx context.Context, r store.Revocation) error {
	if f.on("insertRevocation") {
		return errDown
	}
	return f.fakeStore.InsertRevocation(ctx, r)
}
func (f *failStore) ListUser(ctx context.Context, tid, uid string) ([]store.Session, error) {
	if f.on("listUser") {
		return nil, errDown
	}
	return f.fakeStore.ListUser(ctx, tid, uid)
}
func (f *failStore) User(ctx context.Context, tid, uid string) (store.User, error) {
	if f.on("user") {
		return store.User{}, errDown
	}
	return f.fakeStore.User(ctx, tid, uid)
}

// failKV fails Get/Set/Publish on demand.
type failKV struct {
	*cache.Memory
	get, publish bool
}

func (f *failKV) Get(ctx context.Context, k string) (string, bool, error) {
	if f.get {
		return "", false, errDown
	}
	return f.Memory.Get(ctx, k)
}
func (f *failKV) Publish(ctx context.Context, ch, msg string) error {
	if f.publish {
		return errDown
	}
	return f.Memory.Publish(ctx, ch, msg)
}

func TestFailurePaths(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	fs := &failStore{fakeStore: newFake(clock), fail: map[string]bool{}}
	fs.tenants[tid] = store.Tenant{ID: tid, Status: "active", Kind: "customer", Policy: []byte("{}")}
	kv := &failKV{Memory: cache.NewMemory()}
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	m := New(fs, cache.New(kv), aw)
	m.now = clock
	ctx := context.Background()
	pol := tenant.DefaultPolicy()
	// Entropy and insert failures on Create.
	restore := crypto.SetRand(badReader{})
	if _, _, err := m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: pol}); err == nil {
		t.Fatal("create without entropy")
	}
	restore()
	fs.fail["insert"] = true
	if _, _, err := m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: pol}); !errors.Is(err, errDown) {
		t.Fatal("insert failure ignored")
	}
	fs.fail["insert"] = false
	// Long user agents are clipped; the view is not cached when already expired.
	expired := pol
	expired.SessionLifetime = tenant.Duration(0)
	s, secret, err := m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", UserAgent: strings.Repeat("x", 300), Policy: expired})
	if err != nil || len(s.UserAgent) != 256 {
		t.Fatal(err)
	}
	if _, err := m.Resolve(ctx, secret); !errors.Is(err, ErrNoSession) {
		t.Fatal("expired at creation")
	}
	// Cache read failures fall back to the database; corrupt cache entries are ignored.
	s, secret, _ = m.Create(ctx, CreateParams{TenantID: tid, UserID: "u1", Policy: pol})
	kv.get = true
	if _, err := m.Resolve(ctx, secret); err != nil {
		t.Fatalf("cache failure must fall back: %v", err)
	}
	kv.get = false
	_ = kv.Set(ctx, cache.SessionKey(crypto.HashToken(secret)), "{not json", time.Minute)
	if _, err := m.Resolve(ctx, secret); err != nil {
		t.Fatalf("corrupt cache must fall back: %v", err)
	}
	// Database-path failures: tenant, roles, bad policy, touch.
	_ = kv.Del(ctx, cache.SessionKey(crypto.HashToken(secret)))
	fs.fail["tenant"] = true
	if _, err := m.Resolve(ctx, secret); !errors.Is(err, ErrNoSession) {
		t.Fatal("tenant failure")
	}
	fs.fail["tenant"] = false
	fs.fail["roles"] = true
	if _, err := m.Resolve(ctx, secret); !errors.Is(err, errDown) {
		t.Fatal("roles failure")
	}
	fs.fail["roles"] = false
	tn := fs.tenants[tid]
	tn.Policy = []byte("not json")
	fs.tenants[tid] = tn
	if _, err := m.Resolve(ctx, secret); err == nil {
		t.Fatal("bad policy")
	}
	tn.Policy = []byte("{}")
	fs.tenants[tid] = tn
	now = now.Add(2 * time.Minute)
	fs.fail["touch"] = true
	if _, err := m.Resolve(ctx, secret); err != nil {
		t.Fatalf("touch failure must not end the session: %v", err)
	}
	fs.fail["touch"] = false
	// Revocation failures on every path.
	fs.fail["revoke"] = true
	if err := m.Revoke(ctx, tid, s.ID, ReasonSignout); !errors.Is(err, errDown) {
		t.Fatal("revoke failure")
	}
	fs.fail["revoke"] = false
	fs.fail["insertRevocation"] = true
	if err := m.Revoke(ctx, tid, s.ID, ReasonSignout); !errors.Is(err, errDown) {
		t.Fatal("feed failure")
	}
	if err := m.RevokeUser(ctx, tid, "u1", ReasonAdmin, ""); !errors.Is(err, errDown) {
		t.Fatal("feed failure (user)")
	}
	if err := m.RevokeTenant(ctx, tid, ReasonSuspended); !errors.Is(err, errDown) {
		t.Fatal("feed failure (tenant)")
	}
	fs.fail["insertRevocation"] = false
	kv.publish = true
	if err := m.Revoke(ctx, tid, s.ID, ReasonSignout); !errors.Is(err, errDown) {
		t.Fatal("publish failure")
	}
	kv.publish = false
	fs.fail["revokeUser"] = true
	if err := m.RevokeUser(ctx, tid, "u1", ReasonAdmin, ""); !errors.Is(err, errDown) {
		t.Fatal("revokeUser failure")
	}
	fs.fail["revokeUser"] = false
	fs.fail["listUser"] = true
	if err := m.RevokeUser(ctx, tid, "u1", ReasonAdmin, "keep"); !errors.Is(err, errDown) {
		t.Fatal("listUser failure")
	}
	if _, err := m.ListMine(ctx, tid, "u1", ""); !errors.Is(err, errDown) {
		t.Fatal("list failure")
	}
	fs.fail["listUser"] = false
	fs.fail["revokeTenant"] = true
	if err := m.RevokeTenant(ctx, tid, ReasonSuspended); !errors.Is(err, errDown) {
		t.Fatal("revokeTenant failure")
	}
	fs.fail["revokeTenant"] = false
	_, secretB, _ := m.Create(ctx, CreateParams{TenantID: tid, UserID: "u2", Policy: pol})
	fs.fail["insertRevocation"] = true
	if err := m.RevokeUser(ctx, tid, "u2", ReasonAdmin, "keep-nothing"); !errors.Is(err, errDown) {
		t.Fatal("per-session feed failure")
	}
	fs.fail["insertRevocation"] = false
	_ = secretB
	if err := m.publish(ctx, store.Revocation{Kind: "galaxy"}); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, err := m.Since(ctx, time.Time{}, 5000); err != nil {
		t.Fatal(err)
	}
	if kindOrSystem(tenantctx.Actor{}) != "system" || clip("ab", 5) != "ab" {
		t.Fatal("helpers")
	}
	// Operators are recognised from the cached view; a session-level mark
	// set elsewhere (another instance) is honoured while the view is cached.
	sOp, secOp, _ := m.Create(ctx, CreateParams{TenantID: tid, UserID: "op", Operator: true, Policy: pol})
	if a, err := m.Resolve(ctx, secOp); err != nil || a.Kind != tenantctx.KindOperator {
		t.Fatalf("%+v %v", a, err)
	}
	if err := m.cache.MarkRevoked(ctx, cache.RevokedSessionKey(sOp.ID), now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve(ctx, secOp); !errors.Is(err, ErrNoSession) {
		t.Fatal("session mark ignored")
	}
	// Without a cache the manager still works end to end.
	plain := New(fs, nil, nil)
	plain.now = clock
	_, sec, err := plain.Create(ctx, CreateParams{TenantID: tid, UserID: "u3", Policy: pol})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Resolve(ctx, sec); err != nil {
		t.Fatal(err)
	}
	if err := plain.RevokeUser(ctx, tid, "u3", ReasonAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Resolve(ctx, sec); !errors.Is(err, ErrNoSession) {
		t.Fatal("revoked without cache")
	}
	aw.Close()
	if len(ms.AuditRows) == 0 {
		t.Fatal("audit events expected")
	}
}
