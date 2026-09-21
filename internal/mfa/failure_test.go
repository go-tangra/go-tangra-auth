package mfa

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

var errDown = errors.New("down")

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, errDown }

// flaky serves ok reads from crypto/rand, then fails.
type flaky struct{ ok int }

func (f *flaky) Read(b []byte) (int, error) {
	if f.ok <= 0 {
		return 0, errDown
	}
	f.ok--
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return len(b), nil
}

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
func (f *failing) SetMFA(ctx context.Context, tid, uid string, on bool, enc []byte) error {
	if f.fail["setMFA"] {
		return errDown
	}
	return f.Store.SetMFA(ctx, tid, uid, on, enc)
}
func (f *failing) SetMFACounter(ctx context.Context, tid, uid string, c int64) error {
	if f.fail["counter"] {
		return errDown
	}
	return f.Store.SetMFACounter(ctx, tid, uid, c)
}
func (f *failing) ReplaceRecoveryCodes(ctx context.Context, tid, uid string, h []string) error {
	if f.fail["replace"] {
		return errDown
	}
	return f.Store.ReplaceRecoveryCodes(ctx, tid, uid, h)
}
func (f *failing) ListRecoveryCodeHashes(ctx context.Context, tid, uid string) ([]string, error) {
	if f.fail["list"] {
		return nil, errDown
	}
	return f.Store.ListRecoveryCodeHashes(ctx, tid, uid)
}
func (f *failing) UseRecoveryCode(ctx context.Context, tid, uid, h string) error {
	if f.fail["use"] {
		return errDown
	}
	return f.Store.UseRecoveryCode(ctx, tid, uid, h)
}

type failKV struct {
	*cache.Memory
	set bool
}

func (f *failKV) Set(ctx context.Context, k, v string, ttl time.Duration) error {
	if f.set {
		return errDown
	}
	return f.Memory.Set(ctx, k, v, ttl)
}

func TestFailurePaths(t *testing.T) {
	svc, ms, now := setup(t)
	ctx := context.Background()
	fs := &failing{Store: ms, fail: map[string]bool{}}
	kv := &failKV{Memory: cache.NewMemory()}
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	svc = New(fs, cache.New(kv), svc.env, aw, "Freya")
	svc.now = func() time.Time { return *now }
	alice := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tA}
	fs.fail["user"] = true
	if _, err := svc.Enrol(ctx, alice); !errors.Is(err, errDown) {
		t.Fatal("user failure")
	}
	if _, err := svc.Verify(ctx, tA, "u1", "123456"); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("verify with user failure")
	}
	fs.fail["user"] = false
	restore := crypto.SetRand(badReader{})
	if _, err := svc.Enrol(ctx, alice); err == nil {
		t.Fatal("enrol without entropy")
	}
	restore()
	kv.set = true
	if _, err := svc.Enrol(ctx, alice); !errors.Is(err, errDown) {
		t.Fatal("cache failure")
	}
	restore = crypto.SetRand(&flaky{ok: 1})
	if _, err := svc.Enrol(ctx, alice); err == nil {
		t.Fatal("enrol with sealing failure")
	}
	restore()
	if _, err := New(fs, cache.New(kv), svc.env, nil, "").Enrol(ctx, alice); err == nil {
		t.Fatal("empty issuer must be refused by the otpauth builder")
	}
	kv.set = false
	// Corrupt pending seed.
	_ = kv.Set(ctx, cache.ChallengeKey("enrol:u1"), "garbage", time.Minute)
	if _, err := svc.Confirm(ctx, alice, "123456"); !errors.Is(err, ErrNoPending) {
		t.Fatal("corrupt pending accepted")
	}
	enr, err := svc.Enrol(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	code := func() string { c, _ := totp.GenerateCodeCustom(enr.Secret, *now, opts); return c }
	fs.fail["setMFA"] = true
	if _, err := svc.Confirm(ctx, alice, code()); !errors.Is(err, errDown) {
		t.Fatal("setMFA failure")
	}
	fs.fail["setMFA"] = false
	fs.fail["counter"] = true
	if _, err := svc.Confirm(ctx, alice, code()); !errors.Is(err, errDown) {
		t.Fatal("counter failure")
	}
	fs.fail["counter"] = false
	fs.fail["replace"] = true
	if _, err := svc.Confirm(ctx, alice, code()); !errors.Is(err, errDown) {
		t.Fatal("replace failure")
	}
	fs.fail["replace"] = false
	// The failed regeneration above consumed the pending enrolment.
	if enr, err = svc.Enrol(ctx, alice); err != nil {
		t.Fatal(err)
	}
	restore = crypto.SetRand(badReader{})
	if _, err := svc.Confirm(ctx, alice, code()); err == nil {
		t.Fatal("recovery codes without entropy")
	}
	restore()
	if enr, err = svc.Enrol(ctx, alice); err != nil {
		t.Fatal(err)
	}
	codes, err := svc.Confirm(ctx, alice, code())
	if err != nil {
		t.Fatal(err)
	}
	// Verify failure paths: sealed seed corrupt, counter store, list/use failures.
	*now = now.Add(30 * time.Second)
	fs.fail["counter"] = true
	if _, err := svc.Verify(ctx, tA, "u1", code()); !errors.Is(err, errDown) {
		t.Fatal("counter failure on verify")
	}
	fs.fail["counter"] = false
	fs.fail["list"] = true
	if _, err := svc.Verify(ctx, tA, "u1", codes[0]); !errors.Is(err, errDown) {
		t.Fatal("list failure")
	}
	fs.fail["list"] = false
	fs.fail["use"] = true
	if _, err := svc.Verify(ctx, tA, "u1", codes[0]); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("use failure")
	}
	fs.fail["use"] = false
	u, _ := ms.User(ctx, tA, "u1")
	good := u.MFASecretEnc
	_ = ms.SetMFA(ctx, tA, "u1", true, []byte("corrupt"))
	if _, err := svc.Verify(ctx, tA, "u1", code()); err == nil {
		t.Fatal("corrupt seed accepted")
	}
	_ = ms.SetMFA(ctx, tA, "u1", true, good)
	// Disable / Regenerate failure paths.
	*now = now.Add(30 * time.Second)
	fs.fail["tenant"] = true
	if err := svc.Disable(ctx, alice, code()); !errors.Is(err, errDown) {
		t.Fatal("tenant failure on disable")
	}
	fs.fail["tenant"] = false
	tn := ms.Tenants[tA]
	tn.Policy = []byte("nope")
	ms.AddTenant(tn)
	if err := svc.Disable(ctx, alice, code()); err == nil {
		t.Fatal("bad policy on disable")
	}
	tn.Policy = []byte("{}")
	ms.AddTenant(tn)
	fs.fail["replace"] = true
	if _, err := svc.Regenerate(ctx, alice, code()); !errors.Is(err, errDown) {
		t.Fatal("replace failure on regenerate")
	}
	fs.fail["replace"] = false
	*now = now.Add(30 * time.Second)
	fs.fail["setMFA"] = true
	if err := svc.Disable(ctx, alice, code()); !errors.Is(err, errDown) {
		t.Fatal("setMFA failure on disable")
	}
	fs.fail["setMFA"] = false
	*now = now.Add(30 * time.Second)
	if _, err := svc.Regenerate(ctx, alice, "000000"); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("regenerate with bad code")
	}
	// Salt generation fails after the code bytes were read.
	restore = crypto.SetRand(&flaky{ok: 1})
	if _, err := svc.Regenerate(ctx, alice, code()); err == nil {
		t.Fatal("regenerate without salt entropy")
	}
	restore()
	*now = now.Add(30 * time.Second)
	if _, err := svc.Regenerate(ctx, alice, code()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(30 * time.Second)
	fs.fail["replace"] = true
	if err := svc.Disable(ctx, alice, code()); !errors.Is(err, errDown) {
		t.Fatal("replace failure on disable")
	}
	fs.fail["replace"] = false
	aw.Close()
	if len(ms.AuditRows) == 0 {
		t.Fatal("audit rows expected")
	}
}
