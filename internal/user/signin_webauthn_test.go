package user

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/mfa"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra-auth/v4/internal/webauthn"
	"github.com/go-tangra/go-tangra-auth/v4/internal/webauthn/softkey"
)

const waOrigin = "https://auth.example.org"

type keyFixture struct {
	svc   *Service
	ms    *memstore.Store
	c     *cache.Cache
	aw    *audit.Writer
	mfa   *mfa.Service
	keys  *webauthn.Service
	key   *softkey.Key
	codes []string
	ctx   context.Context
}

// keySetup: carol (u7) signs in with a password and a security key only.
func keySetup(t *testing.T) *keyFixture {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte(`{"lockout_threshold":3,"lockout_duration":"5m"}`)})
	h, _ := password.Hash("correct horse battery")
	ms.AddUser(store.User{ID: "u7", TenantID: tA, Email: "carol@x.test", Status: "active", PasswordHash: &h})
	c := cache.New(cache.NewMemory())
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{4}, 32))
	m := mfa.New(ms, c, env, aw, "Tangra")
	ws, err := webauthn.New(webauthn.Config{RPID: "auth.example.org", Origins: []string{waOrigin}, DisplayName: "Tangra", UserVerification: "preferred", Timeout: 5 * time.Minute}, ms, m, c, aw)
	if err != nil {
		t.Fatal(err)
	}
	f := &keyFixture{ms: ms, c: c, aw: aw, mfa: m, keys: ws, key: softkey.New(waOrigin), ctx: context.Background()}
	carol := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u7", TenantID: tA}
	opts, err := ws.BeginRegistration(f.ctx, carol, "Desk")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(opts)
	resp, _ := f.key.Create(b)
	reg, err := ws.FinishRegistration(f.ctx, carol, resp)
	if err != nil {
		t.Fatal(err)
	}
	f.codes = reg.RecoveryCodes
	sm := session.New(ms, c, nil)
	f.svc = New(ms, c, aw, sm, m)
	f.svc.SetMethods(m)
	f.svc.SetKeys(ws)
	f.svc.SetPad(func(time.Time) {})
	return f
}

func (f *keyFixture) start(t *testing.T) Result {
	t.Helper()
	res, err := f.svc.Start(f.ctx, Input{TenantSlug: "acme", Email: "carol@x.test", Password: "correct horse battery", IP: "7", UserAgent: "ua"})
	if err != nil || !res.MFARequired {
		t.Fatalf("%+v %v", res, err)
	}
	return res
}

func (f *keyFixture) assert(t *testing.T, challenge string, k *softkey.Key) []byte {
	t.Helper()
	opts, err := f.svc.WebAuthnOptions(f.ctx, challenge)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(opts)
	resp, err := k.Get(b)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestSigninWithSecurityKey(t *testing.T) {
	f := keySetup(t)
	res := f.start(t)
	if !slices.Equal(res.MFAMethods, []string{"webauthn", "recovery"}) {
		t.Fatalf("methods %v", res.MFAMethods)
	}
	done, err := f.svc.CompleteWebAuthn(f.ctx, res.Challenge, f.assert(t, res.Challenge, f.key), "7", "ua")
	if err != nil || done.Secret == "" || !slices.Equal(done.Session.AMR, []string{"pwd", "hwk"}) {
		t.Fatalf("%+v %v", done, err)
	}
	keys, _ := f.ms.ListWebAuthnCredentials(f.ctx, tA, "u7")
	if keys[0].LastUsedAt == nil || keys[0].SignCount != 1 {
		t.Fatalf("%+v", keys[0])
	}
	// The pending sign-in is single use.
	if _, err := f.svc.WebAuthnOptions(f.ctx, res.Challenge); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("options after success: %v", err)
	}
	if _, err := f.svc.CompleteWebAuthn(f.ctx, res.Challenge, []byte("{}"), "7", "ua"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("reuse after success: %v", err)
	}
	if _, err := f.svc.WebAuthnOptions(f.ctx, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown challenge: %v", err)
	}
	f.aw.Flush()
	found := false
	for _, r := range f.ms.AuditRows {
		if r.EventType == string(audit.SigninOK) && strings.Contains(string(r.Details), `"amr":["pwd","hwk"]`) {
			found = true
		}
	}
	if !found {
		t.Fatal("signin_ok with amr pwd,hwk not audited")
	}
	// A key-only user without the key signs in with a recovery code.
	res = f.start(t)
	if done, err := f.svc.CompleteMFA(f.ctx, res.Challenge, f.codes[0], "7", "ua"); err != nil || done.Session.AMR[1] != "recovery" {
		t.Fatalf("%+v %v", done, err)
	}
}

// Key and code failures share one counter per account (SC-003).
func TestSharedLockoutAcrossMethods(t *testing.T) {
	f := keySetup(t)
	res := f.start(t)
	if _, err := f.svc.CompleteMFA(f.ctx, res.Challenge, "000000", "7", "ua"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
	evil := *f.key
	evil.Origin = "https://phish.example.org"
	for i := 0; i < 2; i++ {
		if _, err := f.svc.CompleteWebAuthn(f.ctx, res.Challenge, f.assert(t, res.Challenge, &evil), "7", "ua"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if locked, _ := f.c.Locked(f.ctx, "u7"); !locked {
		t.Fatal("one code + two key failures must reach the threshold of 3")
	}
	// Locked: refused before any verification, the genuine key included.
	_ = f.c.KV().Set(f.ctx, cache.ChallengeKey(crypto.HashToken("manual")), `{"TenantID":"`+tA+`","UserID":"u7","Policy":{"lockout_threshold":3,"lockout_duration":"5m"}}`, time.Minute)
	if _, err := f.svc.WebAuthnOptions(f.ctx, "manual"); !errors.Is(err, ErrLocked) {
		t.Fatalf("options while locked: %v", err)
	}
	if _, err := f.svc.CompleteWebAuthn(f.ctx, "manual", []byte("{}"), "7", "ua"); !errors.Is(err, ErrLocked) {
		t.Fatalf("complete while locked: %v", err)
	}
	f.aw.Flush()
	var failed, lockout int
	for _, r := range f.ms.AuditRows {
		switch {
		case r.EventType == string(audit.SigninFailed) && (r.Reason == "mfa_failed" || r.Reason == "locked"):
			failed++
		case r.EventType == string(audit.Lockout):
			lockout++
		}
	}
	if failed != 3 || lockout != 1 {
		t.Fatalf("audit: %d signin_failed, %d lockout", failed, lockout)
	}
}

func TestSigninCloneAndOptionsLimits(t *testing.T) {
	f := keySetup(t)
	res := f.start(t)
	if _, err := f.svc.CompleteWebAuthn(f.ctx, res.Challenge, f.assert(t, res.Challenge, f.key), "7", "ua"); err != nil {
		t.Fatal(err)
	}
	res = f.start(t)
	clone := *f.key
	clone.FreezeCounter = true // still at the counter the genuine key already used
	if _, err := f.svc.CompleteWebAuthn(f.ctx, res.Challenge, f.assert(t, res.Challenge, &clone), "7", "ua"); !errors.Is(err, ErrKeyFlagged) {
		t.Fatalf("clone: %v", err)
	}
	if n, _, _ := f.c.KV().Get(f.ctx, cache.RateKey("fail", "u7")); n != "1" {
		t.Fatalf("clone signal must count as a failure: %q", n)
	}
	// Only a flagged key left: no key to offer.
	if _, err := f.svc.WebAuthnOptions(f.ctx, res.Challenge); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("options with a flagged key only: %v", err)
	}
	if m, _ := f.mfa.Methods(f.ctx, tA, "u7"); !slices.Equal(m, []string{"recovery"}) {
		t.Fatalf("methods %v", m)
	}
	// Options calls are rate limited per account.
	_ = f.ms.InsertWebAuthnCredential(f.ctx, store.WebAuthnCredential{ID: store.NewID(), TenantID: tA, UserID: "u7", CredentialID: bytes.Repeat([]byte{1}, 20), PublicKey: []byte{1}, Name: "Spare"})
	var err error
	for i := 0; i <= AccountLimit && err == nil; i++ {
		_, err = f.svc.WebAuthnOptions(f.ctx, res.Challenge)
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("options flood: %v", err)
	}
}

type errMethods struct{}

func (errMethods) Methods(context.Context, string, string) ([]string, error) {
	return nil, errors.New("down")
}

type errKeys struct{}

func (errKeys) SigninOptions(context.Context, string, string, string) (any, error) {
	return nil, errors.New("down")
}
func (errKeys) VerifySignin(context.Context, string, string, string, []byte) error {
	return errors.New("down")
}

func TestSigninMethodsFallbacks(t *testing.T) {
	f := keySetup(t)
	// Methods cannot be read: every method this instance supports is offered.
	f.svc.SetMethods(errMethods{})
	if res := f.start(t); !slices.Equal(res.MFAMethods, []string{"webauthn", "totp", "recovery"}) {
		t.Fatalf("%v", res.MFAMethods)
	}
	f.svc.SetMethods(nil)
	f.svc.SetKeys(nil)
	res := f.start(t)
	if !slices.Equal(res.MFAMethods, []string{"totp", "recovery"}) {
		t.Fatalf("keys disabled: %v", res.MFAMethods)
	}
	if _, err := f.svc.WebAuthnOptions(f.ctx, res.Challenge); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("options with keys disabled: %v", err)
	}
	if _, err := f.svc.CompleteWebAuthn(f.ctx, res.Challenge, []byte("{}"), "7", "ua"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("complete with keys disabled: %v", err)
	}
	// Keys disabled while the user has keys: the lister's webauthn is dropped.
	f.svc.SetMethods(f.mfa)
	if res := f.start(t); !slices.Equal(res.MFAMethods, []string{"recovery"}) {
		t.Fatalf("%v", res.MFAMethods)
	}
	// Infrastructure errors from the key step surface as errors.
	f.svc.SetKeys(errKeys{})
	res = f.start(t)
	if _, err := f.svc.WebAuthnOptions(f.ctx, res.Challenge); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("options error: %v", err)
	}
	// A corrupt pending challenge is an unknown one.
	_ = f.c.KV().Set(f.ctx, cache.ChallengeKey(crypto.HashToken("corrupt")), "{", time.Minute)
	if _, err := f.svc.WebAuthnOptions(f.ctx, "corrupt"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("corrupt challenge: %v", err)
	}
}
