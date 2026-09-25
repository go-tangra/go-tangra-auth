package password

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

var errDown = errors.New("down")

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, errDown }

type flaky struct{ ok int }

func (f *flaky) Read(b []byte) (int, error) {
	if f.ok <= 0 {
		return 0, errDown
	}
	f.ok--
	for i := range b {
		b[i] = byte(i*3 + 5)
	}
	return len(b), nil
}

// failing wraps the memory store and fails named operations.
type failing struct {
	*memstore.Store
	fail map[string]bool
}

func (f *failing) User(ctx context.Context, tid, uid string) (store.User, error) {
	if f.fail["user"] {
		return store.User{}, errDown
	}
	return f.Store.User(ctx, tid, uid)
}
func (f *failing) Tenant(ctx context.Context, tid string) (store.Tenant, error) {
	if f.fail["tenant"] {
		return store.Tenant{}, errDown
	}
	return f.Store.Tenant(ctx, tid)
}
func (f *failing) SetPassword(ctx context.Context, tid, uid, h string) error {
	if f.fail["setPassword"] {
		return errDown
	}
	return f.Store.SetPassword(ctx, tid, uid, h)
}
func (f *failing) InsertRecoveryRequest(ctx context.Context, r store.RecoveryRequest, ip string) error {
	if f.fail["insertRecovery"] {
		return errDown
	}
	return f.Store.InsertRecoveryRequest(ctx, r, ip)
}
func (f *failing) UseRecoveryRequest(ctx context.Context, h string) (store.RecoveryRequest, error) {
	if f.fail["useRecovery"] {
		return store.RecoveryRequest{}, errDown
	}
	return f.Store.UseRecoveryRequest(ctx, h)
}
func (f *failing) RevokeUser(ctx context.Context, tid, uid, reason, keep string) error {
	if f.fail["revokeUser"] {
		return errDown
	}
	return f.Store.RevokeUser(ctx, tid, uid, reason, keep)
}

func TestFailurePaths(t *testing.T) {
	ctx := context.Background()
	ms, _, ob := setup(t)
	fs := &failing{Store: ms, fail: map[string]bool{}}
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	sm := session.New(fs, cache.New(cache.NewMemory()), aw)
	actor := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tid}
	ch := NewChanger(fs, sm, aw)
	ch.SetPad(func(time.Time) {})
	// Verify clips over-long input and survives a corrupt hash.
	if ok, _ := Verify(strings.Repeat("a", 2000), ""); ok {
		t.Fatal("dummy")
	}
	if ok, _ := Verify(strings.Repeat("a", 2000), *ms.Users[tid+"/alice@x.test"].PasswordHash); ok {
		t.Fatal("clipped input must not verify")
	}
	fs.fail["user"] = true
	if err := ch.Change(ctx, actor, "old-password-1", "new-password-long"); !errors.Is(err, errDown) {
		t.Fatal("user failure")
	}
	fs.fail["user"] = false
	fs.fail["tenant"] = true
	if err := ch.Change(ctx, actor, "old-password-1", "new-password-long"); !errors.Is(err, errDown) {
		t.Fatal("tenant failure")
	}
	fs.fail["tenant"] = false
	tn := ms.Tenants[tid]
	tn.Policy = []byte("nope")
	ms.AddTenant(tn)
	if err := ch.Change(ctx, actor, "old-password-1", "new-password-long"); err == nil {
		t.Fatal("bad policy")
	}
	tn.Policy = []byte(`{"password_min_length":10}`)
	ms.AddTenant(tn)
	restore := crypto.SetRand(badReader{})
	if err := ch.Change(ctx, actor, "old-password-1", "new-password-long"); !errors.Is(err, errDown) {
		t.Fatal("hash without entropy")
	}
	restore()
	fs.fail["setPassword"] = true
	if err := ch.Change(ctx, actor, "old-password-1", "new-password-long"); !errors.Is(err, errDown) {
		t.Fatal("setPassword failure")
	}
	fs.fail["setPassword"] = false
	fs.fail["revokeUser"] = true
	if err := ch.Change(ctx, actor, "old-password-1", "new-password-long"); !errors.Is(err, errDown) {
		t.Fatal("revoke failure")
	}
	fs.fail["revokeUser"] = false
	// The revoke failure above happened after the new hash was stored.
	if err := ch.Change(ctx, actor, "new-password-long", "another-new-password"); err != nil {
		t.Fatal(err)
	}
	// Recovery: entropy, insert, encode-independent enqueue, complete paths.
	rec := NewRecovery(fs, ob, sm, aw, "https://auth.example.org")
	rec.SetPad(func(time.Time) {})
	restore = crypto.SetRand(badReader{})
	if err := rec.Request(ctx, "acme", "alice@x.test", "ip"); err != nil {
		t.Fatal("request must never fail visibly")
	}
	restore()
	restore = crypto.SetRand(&flaky{ok: 1})
	if err := rec.Request(ctx, "acme", "alice@x.test", "ip"); err != nil {
		t.Fatal("encode failure must stay silent")
	}
	restore()
	fs.fail["insertRecovery"] = true
	if err := rec.Request(ctx, "acme", "alice@x.test", "ip"); err != nil {
		t.Fatal(err)
	}
	fs.fail["insertRecovery"] = false
	if n := len(ms.Outbox); n != 0 {
		t.Fatalf("nothing should be queued after failures, got %d", n)
	}
	if err := rec.Request(ctx, "acme", "alice@x.test", "ip"); err != nil || len(ms.Outbox) != 1 {
		t.Fatal(err)
	}
	tok := recoveryToken(t, ob, ms.Outbox[0])
	fs.fail["tenant"] = true
	if err := rec.Complete(ctx, tok, "brand-new-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("tenant failure on complete")
	}
	fs.fail["tenant"] = false
	tn.Policy = []byte("nope")
	ms.AddTenant(tn)
	if err := rec.Complete(ctx, tok, "brand-new-password"); err == nil {
		t.Fatal("bad policy on complete")
	}
	tn.Policy = []byte("{}")
	ms.AddTenant(tn)
	fs.fail["useRecovery"] = true
	if err := rec.Complete(ctx, tok, "brand-new-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("use failure")
	}
	fs.fail["useRecovery"] = false
	restore = crypto.SetRand(badReader{})
	if err := rec.Complete(ctx, tok, "brand-new-password"); !errors.Is(err, errDown) {
		t.Fatal("hash without entropy on complete")
	}
	restore()
	// The token was consumed by the failed attempt above; request another.
	_ = rec.Request(ctx, "acme", "alice@x.test", "ip")
	tok = recoveryToken(t, ob, ms.Outbox[len(ms.Outbox)-1])
	fs.fail["setPassword"] = true
	if err := rec.Complete(ctx, tok, "brand-new-password"); !errors.Is(err, errDown) {
		t.Fatal("setPassword failure on complete")
	}
	fs.fail["setPassword"] = false
	_ = rec.Request(ctx, "acme", "alice@x.test", "ip")
	tok = recoveryToken(t, ob, ms.Outbox[len(ms.Outbox)-1])
	fs.fail["revokeUser"] = true
	if err := rec.Complete(ctx, tok, "brand-new-password"); !errors.Is(err, errDown) {
		t.Fatal("revoke failure on complete")
	}
	fs.fail["revokeUser"] = false
	// Suspended tenant refuses completion; inactive users are never mailed.
	_ = rec.Request(ctx, "acme", "alice@x.test", "ip")
	tok = recoveryToken(t, ob, ms.Outbox[len(ms.Outbox)-1])
	tn.Status = "suspended"
	ms.AddTenant(tn)
	if err := rec.Complete(ctx, tok, "brand-new-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatal("suspended tenant completion")
	}
	before := len(ms.Outbox)
	if err := rec.Request(ctx, "acme", "alice@x.test", "ip"); err != nil || len(ms.Outbox) != before {
		t.Fatal("suspended tenant must not mail")
	}
	tn.Status = "active"
	ms.AddTenant(tn)
	_ = ms.UpdateUserStatus(ctx, tid, "u1", "deactivated")
	if err := rec.Request(ctx, "acme", "alice@x.test", "ip"); err != nil || len(ms.Outbox) != before {
		t.Fatal("deactivated user must not mail")
	}
}
