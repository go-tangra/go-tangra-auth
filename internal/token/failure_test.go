package token

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// flaky serves ok reads, then fails (reaches the "seal failed" branch).
type flaky struct{ ok int }

func (f *flaky) Read(b []byte) (int, error) {
	if f.ok <= 0 {
		return 0, errors.New("no entropy")
	}
	f.ok--
	for i := range b {
		b[i] = byte(i*5 + 1)
	}
	return len(b), nil
}

// failKeys wraps MemKeys and fails selected operations.
type failKeys struct {
	*MemKeys
	list, insert, setState, remove bool
}

var errStore = errors.New("store down")

func (f *failKeys) List(ctx context.Context) ([]store.SigningKey, error) {
	if f.list {
		return nil, errStore
	}
	return f.MemKeys.List(ctx)
}
func (f *failKeys) Insert(ctx context.Context, k store.SigningKey) error {
	if f.insert {
		return errStore
	}
	return f.MemKeys.Insert(ctx, k)
}
func (f *failKeys) SetState(ctx context.Context, kid, st string, at time.Time) error {
	if f.setState {
		return errStore
	}
	return f.MemKeys.SetState(ctx, kid, st, at)
}
func (f *failKeys) Remove(ctx context.Context, kid string) error {
	if f.remove {
		return errStore
	}
	return f.MemKeys.Remove(ctx, kid)
}

func TestRingDefaultsAndFailures(t *testing.T) {
	ctx := context.Background()
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{3}, 32))
	// Defaults for zero/out-of-range config.
	r := NewRing(NewMemKeys(), env, Config{AccessLifetime: time.Hour, ClockSkew: time.Hour})
	if r.cfg.AccessLifetime != 15*time.Minute || r.cfg.RotationInterval != 24*time.Hour || r.cfg.RetiringPeriod != 30*time.Minute || r.cfg.ClockSkew != 60*time.Second {
		t.Fatalf("defaults %+v", r.cfg)
	}
	// Issue without any key.
	if _, _, err := NewIssuer(r, "iss").Issue(Request{UserID: "u", TenantID: "t", SessionID: "s"}); !errors.Is(err, ErrNoActiveKey) {
		t.Fatal("empty ring issued")
	}
	// Randomness failure during generation.
	restore := crypto.SetRand(badReader{})
	if _, err := GenerateKey(env, time.Now()); err == nil {
		t.Fatal("generate without entropy")
	}
	if err := r.Rotate(ctx); err == nil {
		t.Fatal("rotate without entropy")
	}
	restore()
	restore = crypto.SetRand(&flaky{ok: 1})
	if _, err := GenerateKey(env, time.Now()); err == nil {
		t.Fatal("generate with sealing failure")
	}
	restore()
	// Store failures on every path.
	fk := &failKeys{MemKeys: NewMemKeys(), list: true}
	if err := NewRing(fk, env, Config{}).Load(ctx); err == nil {
		t.Fatal("list failure ignored")
	}
	fk = &failKeys{MemKeys: NewMemKeys(), insert: true}
	if err := NewRing(fk, env, Config{}).Load(ctx); err == nil {
		t.Fatal("insert failure ignored")
	}
	fk = &failKeys{MemKeys: NewMemKeys()}
	now := time.Now()
	r = NewRing(fk, env, Config{RotationInterval: time.Hour, RetiringPeriod: time.Minute})
	r.now = func() time.Time { return now }
	if err := r.Load(ctx); err != nil {
		t.Fatal(err)
	}
	fk.setState = true
	if err := r.Rotate(ctx); err == nil {
		t.Fatal("setState failure on rotate ignored")
	}
	fk.setState = false
	// Insert failure after the old key was retired: the old key is restored to active.
	fk.insert = true
	if err := r.Rotate(ctx); err == nil {
		t.Fatal("insert failure on rotate ignored")
	}
	fk.insert = false
	active := 0
	for _, k := range r.keys {
		if k.State == StateActive {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("active key must be restored after a failed rotation: %d", active)
	}
	if err := r.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	fk.setState = true
	if err := r.Sweep(ctx); err == nil {
		t.Fatal("setState failure on sweep ignored")
	}
	fk.setState = false
	if err := r.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Minute)
	fk.remove = true
	if err := r.Sweep(ctx); err == nil {
		t.Fatal("remove failure ignored")
	}
	// Run reports errors through onError.
	got := make(chan error, 1)
	ctx2, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancel()
	r.Run(ctx2, 5*time.Millisecond, func(err error) {
		select {
		case got <- err:
		default:
		}
	})
	if len(got) == 0 {
		t.Fatal("onError not called")
	}
	// Unknown kid in the memory store; sealed key of the wrong size.
	if err := NewMemKeys().SetState(ctx, "nope", StateRetired, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unknown kid")
	}
	k, _ := GenerateKey(env, now)
	short, _ := env.Encrypt([]byte("short"), []byte("signing_key:"+k.KID))
	k.PrivateEnc = short
	if _, err := OpenKey(env, k); err == nil {
		t.Fatal("wrong size accepted")
	}
	// Signing with a broken private key surfaces as an error, not a panic.
	pub, _, _ := ed25519.GenerateKey(nil)
	r.mu.Lock()
	r.keys = map[string]*ringKey{"broken": {SigningKey: store.SigningKey{KID: "broken", PublicKey: pub, State: StateActive, CreatedAt: now.Add(time.Hour)}, priv: nil}}
	r.mu.Unlock()
	iss := NewIssuer(r, "iss")
	if _, _, err := iss.Issue(Request{UserID: "u", TenantID: "t", SessionID: "s"}); !errors.Is(err, ErrBrokenKey) {
		t.Fatal("broken key signed")
	}
	// A signer that is not Ed25519 is refused by the JWT layer.
	rsaKey, _ := rsa.GenerateKey(crypto.Rand(), 2048)
	r.mu.Lock()
	r.keys["rsa"] = &ringKey{SigningKey: store.SigningKey{KID: "rsa", PublicKey: pub, State: StateActive, CreatedAt: now.Add(2 * time.Hour)}, priv: rsaKey}
	r.mu.Unlock()
	if _, _, err := iss.Issue(Request{UserID: "u", TenantID: "t", SessionID: "s"}); err == nil || errors.Is(err, ErrBrokenKey) {
		t.Fatalf("foreign signer accepted: %v", err)
	}
}
