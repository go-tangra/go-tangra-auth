package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/mfa"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra-auth/v4/internal/webauthn/softkey"
)

const (
	tA     = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tP     = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	rpID   = "auth.example.org"
	origin = "https://auth.example.org"
)

var errDown = errors.New("down")

// failStore injects errors into the persistence the service uses.
type failStore struct {
	*memstore.Store
	fail map[string]bool
}

func (f *failStore) User(ctx context.Context, tid, uid string) (store.User, error) {
	if f.fail["user"] {
		return store.User{}, errDown
	}
	return f.Store.User(ctx, tid, uid)
}
func (f *failStore) Tenant(ctx context.Context, tid string) (store.Tenant, error) {
	if f.fail["tenant"] {
		return store.Tenant{}, errDown
	}
	return f.Store.Tenant(ctx, tid)
}
func (f *failStore) WebAuthnHandle(ctx context.Context, tid, uid string) ([]byte, error) {
	if f.fail["handle"] {
		return nil, errDown
	}
	return f.Store.WebAuthnHandle(ctx, tid, uid)
}
func (f *failStore) EnsureWebAuthnHandle(ctx context.Context, tid, uid string, c []byte) ([]byte, error) {
	if f.fail["ensure"] {
		return nil, errDown
	}
	return f.Store.EnsureWebAuthnHandle(ctx, tid, uid, c)
}
func (f *failStore) ListWebAuthnCredentials(ctx context.Context, tid, uid string) ([]store.WebAuthnCredential, error) {
	if f.fail["list"] {
		return nil, errDown
	}
	if f.fail["empty"] {
		return nil, nil
	}
	return f.Store.ListWebAuthnCredentials(ctx, tid, uid)
}
func (f *failStore) InsertWebAuthnCredential(ctx context.Context, c store.WebAuthnCredential) error {
	if f.fail["insert"] {
		return errDown
	}
	return f.Store.InsertWebAuthnCredential(ctx, c)
}
func (f *failStore) RenameWebAuthnCredential(ctx context.Context, tid, uid, id, name string) error {
	if f.fail["rename"] {
		return errDown
	}
	return f.Store.RenameWebAuthnCredential(ctx, tid, uid, id, name)
}
func (f *failStore) DeleteWebAuthnCredential(ctx context.Context, tid, uid, id string) error {
	if f.fail["delete"] {
		return errDown
	}
	return f.Store.DeleteWebAuthnCredential(ctx, tid, uid, id)
}
func (f *failStore) UpdateWebAuthnUse(ctx context.Context, tid, id string, n int64, bs bool) error {
	if f.fail["use"] {
		return errDown
	}
	return f.Store.UpdateWebAuthnUse(ctx, tid, id, n, bs)
}
func (f *failStore) FlagWebAuthnClone(ctx context.Context, tid, id string) error {
	if f.fail["flag"] {
		return errDown
	}
	return f.Store.FlagWebAuthnClone(ctx, tid, id)
}

// failFactors injects errors into the shared factor rules.
type failFactors struct {
	*mfa.Service
	fail map[string]bool
}

func (f *failFactors) KeyAdded(ctx context.Context, a tenantctx.Actor) ([]string, error) {
	if f.fail["added"] {
		return nil, errDown
	}
	return f.Service.KeyAdded(ctx, a)
}
func (f *failFactors) KeyRemoved(ctx context.Context, a tenantctx.Actor) error {
	if f.fail["removed"] {
		return errDown
	}
	return f.Service.KeyRemoved(ctx, a)
}

type failKV struct {
	*cache.Memory
	set, getdel bool
}

func (f *failKV) Set(ctx context.Context, k, v string, ttl time.Duration) error {
	if f.set {
		return errDown
	}
	return f.Memory.Set(ctx, k, v, ttl)
}
func (f *failKV) GetDel(ctx context.Context, k string) (string, bool, error) {
	if f.getdel {
		return "", false, errDown
	}
	return f.Memory.GetDel(ctx, k)
}

type fixture struct {
	svc        *Service
	ms         *memstore.Store
	fs         *failStore
	ff         *failFactors
	kv         *failKV
	c          *cache.Cache
	aw         *audit.Writer
	alice, bob tenantctx.Actor
	op         tenantctx.Actor
	ctx        context.Context
	mfa        *mfa.Service
	cfg        Config
}

func setup(t *testing.T, uv string) *fixture {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte(`{"lockout_threshold":3,"lockout_duration":"5m"}`)})
	ms.AddTenant(store.Tenant{ID: tP, Slug: "platform", Status: "active", Kind: "platform", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u1", TenantID: tA, Email: "alice@x.test", DisplayName: "Alice", Status: "active"})
	ms.AddUser(store.User{ID: "u2", TenantID: tA, Email: "bob@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "op", TenantID: tP, Email: "ops@x.test", Status: "active"})
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{9}, 32))
	kv := &failKV{Memory: cache.NewMemory()}
	c := cache.New(kv)
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	m := mfa.New(ms, c, env, aw, "Tangra")
	fs := &failStore{Store: ms, fail: map[string]bool{}}
	ff := &failFactors{Service: m, fail: map[string]bool{}}
	cfg := Config{RPID: rpID, Origins: []string{origin}, DisplayName: "Tangra", UserVerification: uv, Timeout: 5 * time.Minute}
	svc, err := New(cfg, fs, ff, c, aw)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, ms: ms, fs: fs, ff: ff, kv: kv, c: c, aw: aw, mfa: m, cfg: cfg, ctx: context.Background(),
		alice: tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tA},
		bob:   tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u2", TenantID: tA},
		op:    tenantctx.Actor{Kind: tenantctx.KindOperator, UserID: "op", TenantID: tP}}
}

func js(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fixture) begin(t *testing.T, a tenantctx.Actor, name string) []byte {
	t.Helper()
	opts, err := f.svc.BeginRegistration(f.ctx, a, name)
	if err != nil {
		t.Fatal(err)
	}
	return js(t, opts)
}

func (f *fixture) register(t *testing.T, a tenantctx.Actor, k *softkey.Key, name string) Registered {
	t.Helper()
	resp, err := k.Create(f.begin(t, a, name))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := f.svc.FinishRegistration(f.ctx, a, resp)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func (f *fixture) signinResponse(t *testing.T, ref string, a tenantctx.Actor, k *softkey.Key) []byte {
	t.Helper()
	opts, err := f.svc.SigninOptions(f.ctx, ref, a.TenantID, a.UserID)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := k.Get(js(t, opts))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (f *fixture) stepUp(t *testing.T, a tenantctx.Actor, k *softkey.Key) []byte {
	t.Helper()
	opts, err := f.svc.StepUpOptions(f.ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := k.Get(js(t, opts))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (f *fixture) keys(t *testing.T, a tenantctx.Actor) []store.WebAuthnCredential {
	t.Helper()
	keys, _ := f.ms.ListWebAuthnCredentials(f.ctx, a.TenantID, a.UserID)
	return keys
}

func (f *fixture) auditTypes() string {
	f.aw.Flush()
	var out []string
	for _, r := range f.ms.AuditRows {
		out = append(out, r.EventType+":"+r.Outcome+":"+string(r.Details))
	}
	return strings.Join(out, "\n")
}

func TestRegisterAndSignInEndToEnd(t *testing.T) {
	f := setup(t, "preferred")
	desk := softkey.New(origin)
	raw := f.begin(t, f.alice, "  YubiKey 5C – desk ")
	var opts struct {
		PublicKey struct {
			RP struct {
				ID, Name string
			} `json:"rp"`
			User struct {
				ID, Name, DisplayName string
			} `json:"user"`
			Attestation            string `json:"attestation"`
			AuthenticatorSelection struct {
				ResidentKey      string `json:"residentKey"`
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
			ExcludeCredentials []any `json:"excludeCredentials"`
			Timeout            int   `json:"timeout"`
		} `json:"publicKey"`
	}
	_ = json.Unmarshal(raw, &opts)
	p := opts.PublicKey
	handle, _ := f.ms.WebAuthnHandle(f.ctx, tA, "u1")
	if p.RP.ID != rpID || p.RP.Name != "Tangra" || p.User.Name != "alice@x.test" || p.User.DisplayName != "Alice" || p.Attestation != "none" ||
		p.AuthenticatorSelection.ResidentKey != "discouraged" || p.AuthenticatorSelection.UserVerification != "preferred" || len(p.ExcludeCredentials) != 0 ||
		p.Timeout != 300000 || len(handle) != 32 || p.User.ID != base64.RawURLEncoding.EncodeToString(handle) || strings.Contains(string(raw), "u1") {
		t.Fatalf("creation options %s", raw)
	}
	resp, _ := desk.Create(raw)
	reg, err := f.svc.FinishRegistration(f.ctx, f.alice, resp)
	if err != nil || reg.Key.Name != "YubiKey 5C – desk" || len(reg.RecoveryCodes) != mfa.RecoveryCount || reg.Key.Flagged || reg.Key.CreatedAt.IsZero() {
		t.Fatalf("%+v %v", reg, err)
	}
	if u, _ := f.ms.User(f.ctx, tA, "u1"); !u.MFAEnabled {
		t.Fatal("first key must turn the second step on")
	}
	// The second key: no new codes; the first key is excluded.
	travel := softkey.New(origin)
	raw = f.begin(t, f.alice, "Travel")
	if !bytes.Contains(raw, []byte(base64.RawURLEncoding.EncodeToString(desk.ID))) {
		t.Fatalf("first key not excluded: %s", raw)
	}
	resp, _ = travel.Create(raw)
	if reg2, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); err != nil || reg2.RecoveryCodes != nil {
		t.Fatalf("%+v %v", reg2, err)
	}
	// Sign in with either key; counter and last use are recorded.
	if err := f.svc.VerifySignin(f.ctx, "ref1", tA, "u1", f.signinResponse(t, "ref1", f.alice, desk)); err != nil {
		t.Fatal(err)
	}
	for _, k := range f.keys(t, f.alice) {
		if bytes.Equal(k.CredentialID, desk.ID) && (k.SignCount != 1 || k.LastUsedAt == nil) {
			t.Fatalf("use not recorded: %+v", k)
		}
	}
	if err := f.svc.VerifySignin(f.ctx, "ref2", tA, "u1", f.signinResponse(t, "ref2", f.alice, travel)); err != nil {
		t.Fatal(err)
	}
	a := f.auditTypes()
	if !strings.Contains(a, `mfa_enrolled:ok:{"aaguid":"736f6674-6b65-792d-6161-677569642d31","method":"webauthn"}`) {
		t.Fatalf("audit %s", a)
	}
	id := base64.RawURLEncoding.EncodeToString(desk.ID)
	if strings.Contains(a, id) {
		t.Fatal("credential id in audit")
	}
}

func TestRegistrationRefusals(t *testing.T) {
	f := setup(t, "preferred")
	for _, name := range []string{"", "   ", strings.Repeat("x", 65), "bad\x00name", "tab\tname", string([]byte{0xff})} {
		if _, err := f.svc.BeginRegistration(f.ctx, f.alice, name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q: %v", name, err)
		}
	}
	if n, err := NormalizeName(strings.Repeat("é", 64)); err != nil || n == "" {
		t.Fatal("64 characters must be accepted")
	}
	desk := softkey.New(origin)
	f.register(t, f.alice, desk, "Desk")
	if _, err := f.svc.BeginRegistration(f.ctx, f.alice, "desk"); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("name taken (case-insensitive): %v", err)
	}
	// No ceremony, replay, garbage, oversized.
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, []byte("{}")); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("without ceremony: %v", err)
	}
	k := softkey.New(origin)
	resp, _ := k.Create(f.begin(t, f.alice, "Spare"))
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, []byte("not json")); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("garbage: %v", err)
	}
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatal("the ceremony is single use: a failed attempt consumes it")
	}
	f.begin(t, f.alice, "Spare")
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, bytes.Repeat([]byte(" "), MaxResponseBytes+1)); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("oversized: %v", err)
	}
	// Duplicate credential (the browser's exclusion list is ignored by the soft key).
	resp, _ = desk.Create(f.begin(t, f.alice, "Again"))
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); !errors.Is(err, ErrAlreadyRegistered) {
		t.Fatalf("duplicate: %v", err)
	}
	// Name taken between begin and finish.
	resp, _ = softkey.New(origin).Create(f.begin(t, f.alice, "Race"))
	_ = f.ms.InsertWebAuthnCredential(f.ctx, store.WebAuthnCredential{ID: store.NewID(), TenantID: tA, UserID: "u1", CredentialID: bytes.Repeat([]byte{7}, 20), Name: "RACE"})
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("name race: %v", err)
	}
	// Protocol refusals: origin, relying party, presence, bounds.
	for name, mut := range map[string]func(*softkey.Key){
		"wrong origin":     func(k *softkey.Key) { k.Origin = "https://evil.example.org" },
		"wrong rp id":      func(k *softkey.Key) { k.RPID = "evil.example.org" },
		"no user presence": func(k *softkey.Key) { k.NoPresence = true },
		"wrong type":       func(k *softkey.Key) { k.Type = "webauthn.get" },
		"short cred id":    func(k *softkey.Key) { k.ID = k.ID[:8] },
		"too many transports": func(k *softkey.Key) {
			k.Transports = []string{"usb", "nfc", "ble", "internal", "hybrid", "smart-card", "usb", "nfc", "ble"}
		},
		"backup state without eligibility": func(k *softkey.Key) { k.BackupState = true },
	} {
		k := softkey.New(origin)
		mut(k)
		resp, _ := k.Create(f.begin(t, f.alice, "Neg "+name))
		if _, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); !errors.Is(err, ErrRegistrationFailed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A ceremony of another purpose or user is never accepted.
	f.register(t, f.bob, softkey.New(origin), "Bob key")
	if _, err := f.svc.StepUpOptions(f.ctx, f.bob); err != nil {
		t.Fatal(err)
	}
	stepup, _, _ := f.kv.Memory.GetDel(f.ctx, cache.WebAuthnKey("stepup", "u2"))
	_ = f.kv.Memory.Set(f.ctx, cache.WebAuthnKey("reg", "u2"), stepup, time.Minute)
	resp, _ = softkey.New(origin).Create([]byte(`{"publicKey":{"challenge":"AAAAAAAAAAAAAAAAAAAAAA","rp":{"id":"auth.example.org"}}}`))
	if _, err := f.svc.FinishRegistration(f.ctx, f.bob, resp); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("foreign purpose: %v", err)
	}
	raw := f.begin(t, f.alice, "Stolen")
	rec, _, _ := f.kv.Memory.GetDel(f.ctx, cache.WebAuthnKey("reg", "u1"))
	_ = f.kv.Memory.Set(f.ctx, cache.WebAuthnKey("reg", "u2"), rec, time.Minute)
	resp, _ = softkey.New(origin).Create(raw)
	if _, err := f.svc.FinishRegistration(f.ctx, f.bob, resp); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("another user's ceremony: %v", err)
	}
	// An expired ceremony (the library enforces the timeout).
	raw = f.begin(t, f.alice, "Late")
	rec, _, _ = f.kv.Memory.GetDel(f.ctx, cache.WebAuthnKey("reg", "u1"))
	var c ceremony
	_ = json.Unmarshal([]byte(rec), &c)
	c.Session.Expires = time.Now().Add(-time.Second)
	_ = f.kv.Memory.Set(f.ctx, cache.WebAuthnKey("reg", "u1"), string(js(t, c)), time.Minute)
	resp, _ = softkey.New(origin).Create(raw)
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("expired: %v", err)
	}
}

func TestKeyLimit(t *testing.T) {
	f := setup(t, "preferred")
	for i := 0; i < MaxKeys; i++ {
		f.register(t, f.alice, softkey.New(origin), "Key "+string(rune('A'+i)))
	}
	if _, err := f.svc.BeginRegistration(f.ctx, f.alice, "Eleventh"); !errors.Is(err, ErrKeyLimit) {
		t.Fatalf("begin over the limit: %v", err)
	}
	// Finish re-checks the limit (a key added from another tab meanwhile).
	_ = f.ms.DeleteWebAuthnCredential(f.ctx, tA, "u1", f.keys(t, f.alice)[0].ID)
	raw := f.begin(t, f.alice, "Late tenth")
	_ = f.ms.InsertWebAuthnCredential(f.ctx, store.WebAuthnCredential{ID: store.NewID(), TenantID: tA, UserID: "u1", CredentialID: bytes.Repeat([]byte{9}, 20), Name: "Sneaked in"})
	resp, _ := softkey.New(origin).Create(raw)
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); !errors.Is(err, ErrKeyLimit) {
		t.Fatalf("finish over the limit: %v", err)
	}
}

func TestUserVerificationRequired(t *testing.T) {
	f := setup(t, "required")
	k := softkey.New(origin)
	resp, _ := k.Create(f.begin(t, f.alice, "No PIN"))
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); !errors.Is(err, ErrRegistrationFailed) {
		t.Fatalf("registration without UV: %v", err)
	}
	k.UserVerified = true
	f.register(t, f.alice, k, "With PIN")
	k.UserVerified = false
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", f.signinResponse(t, "r", f.alice, k)); !errors.Is(err, ErrAssertionFailed) {
		t.Fatalf("assertion without UV: %v", err)
	}
	k.UserVerified = true
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", f.signinResponse(t, "r", f.alice, k)); err != nil {
		t.Fatal(err)
	}
}

func TestAssertionRefusals(t *testing.T) {
	f := setup(t, "preferred")
	if _, err := f.svc.SigninOptions(f.ctx, "r", tA, "u1"); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("no keys: %v", err)
	}
	desk := softkey.New(origin)
	f.register(t, f.alice, desk, "Desk")
	bobKey := softkey.New(origin)
	f.register(t, f.bob, bobKey, "Bob")
	// Replay of a verified response and of a consumed ceremony.
	resp := f.signinResponse(t, "r", f.alice, desk)
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", resp); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", resp); !errors.Is(err, ErrAssertionFailed) {
		t.Fatalf("replay: %v", err)
	}
	// Ceremony bound to the reference and the user.
	resp = f.signinResponse(t, "r", f.alice, desk)
	if err := f.svc.VerifySignin(f.ctx, "other", tA, "u1", resp); !errors.Is(err, ErrAssertionFailed) {
		t.Fatalf("other reference: %v", err)
	}
	resp = f.signinResponse(t, "r", f.alice, desk)
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u2", resp); !errors.Is(err, ErrAssertionFailed) {
		t.Fatalf("other user: %v", err)
	}
	for name, mut := range map[string]func(k *softkey.Key){
		"wrong origin":     func(k *softkey.Key) { k.Origin = "https://evil.example.org" },
		"wrong rp id":      func(k *softkey.Key) { k.RPID = "evil.example.org" },
		"no user presence": func(k *softkey.Key) { k.NoPresence = true },
		"wrong type":       func(k *softkey.Key) { k.Type = "webauthn.create" },
		"backup flip":      func(k *softkey.Key) { k.BackupEligible = true },
	} {
		k := *desk
		mut(&k)
		if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", f.signinResponse(t, "r", f.alice, &k)); !errors.Is(err, ErrAssertionFailed) {
			t.Errorf("%s: %v", name, err)
		}
		desk.Counter = k.Counter
	}
	// Another user's key and garbage.
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", f.signinResponse(t, "r", f.alice, bobKey)); !errors.Is(err, ErrAssertionFailed) {
		t.Fatalf("bob's key for alice: %v", err)
	}
	_, _ = f.svc.SigninOptions(f.ctx, "r", tA, "u1")
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", []byte("{")); !errors.Is(err, ErrAssertionFailed) {
		t.Fatalf("garbage: %v", err)
	}
	if _, err := ParseAssertion(make([]byte, MaxResponseBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if _, err := ParseCreation(make([]byte, MaxResponseBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
}

// A counter that does not increase signals a cloned key: refused, flagged,
// audited, and the flagged key stays refused.
func TestCloneSignal(t *testing.T) {
	f := setup(t, "preferred")
	desk := softkey.New(origin)
	f.register(t, f.alice, desk, "Desk")
	spare := softkey.New(origin)
	f.register(t, f.alice, spare, "Spare")
	for i := 0; i < 3; i++ {
		if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", f.signinResponse(t, "r", f.alice, desk)); err != nil {
			t.Fatal(err)
		}
	}
	clone := *desk
	clone.Counter = 1 // the clone was copied earlier
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", f.signinResponse(t, "r", f.alice, &clone)); !errors.Is(err, ErrKeyFlagged) {
		t.Fatalf("clone: %v", err)
	}
	var flagged store.WebAuthnCredential
	for _, k := range f.keys(t, f.alice) {
		if bytes.Equal(k.CredentialID, desk.ID) {
			flagged = k
		}
	}
	if flagged.CloneFlaggedAt == nil || flagged.SignCount != 3 {
		t.Fatalf("%+v", flagged)
	}
	if a := f.auditTypes(); !strings.Contains(a, `mfa_clone_suspected:refused:{"ceremony":"signin"}`) {
		t.Fatalf("audit %s", a)
	}
	// Even the genuine key is refused now; options no longer offer it.
	raw, _ := f.svc.SigninOptions(f.ctx, "r", tA, "u1")
	if bytes.Contains(js(t, raw), []byte(base64.RawURLEncoding.EncodeToString(desk.ID))) {
		t.Fatal("flagged key offered")
	}
	resp, _ := desk.Get(js(t, raw))
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", resp); !errors.Is(err, ErrKeyFlagged) {
		t.Fatalf("flagged key: %v", err)
	}
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", f.signinResponse(t, "r", f.alice, spare)); err != nil {
		t.Fatalf("the other key keeps working: %v", err)
	}
	// Keys that never count (always 0) are not flagged.
	zero := softkey.New(origin)
	zero.FreezeCounter = true
	f.register(t, f.bob, zero, "Counterless")
	for i := 0; i < 2; i++ {
		if err := f.svc.VerifySignin(f.ctx, "b", tA, "u2", f.signinResponse(t, "b", f.bob, zero)); err != nil {
			t.Fatalf("counter 0: %v", err)
		}
	}
}

func TestRenameAndRemove(t *testing.T) {
	f := setup(t, "preferred")
	desk := softkey.New(origin)
	reg := f.register(t, f.alice, desk, "Desk")
	travel := softkey.New(origin)
	reg2 := f.register(t, f.alice, travel, "Travel")
	if k, err := f.svc.Rename(f.ctx, f.alice, reg.Key.ID, "  Office "); err != nil || k.Name != "Office" || k.ID != reg.Key.ID {
		t.Fatalf("%+v %v", k, err)
	}
	if _, err := f.svc.Rename(f.ctx, f.alice, reg.Key.ID, ""); !errors.Is(err, ErrInvalidName) {
		t.Fatal(err)
	}
	if _, err := f.svc.Rename(f.ctx, f.alice, reg.Key.ID, "travel"); !errors.Is(err, ErrNameTaken) {
		t.Fatal(err)
	}
	if _, err := f.svc.Rename(f.ctx, f.bob, reg.Key.ID, "Mine"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another user's key: %v", err)
	}
	// Unknown key, no confirmation, wrong code (counts toward lockout).
	if err := f.svc.Remove(f.ctx, f.alice, "nope", Confirmation{Code: reg.RecoveryCodes[0]}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := f.svc.Remove(f.ctx, f.alice, reg.Key.ID, Confirmation{}); !errors.Is(err, ErrConfirmationFailed) {
		t.Fatal(err)
	}
	if err := f.svc.Remove(f.ctx, f.alice, reg.Key.ID, Confirmation{Code: "ZZZZZ-ZZZZZ"}); !errors.Is(err, ErrConfirmationFailed) {
		t.Fatal(err)
	}
	if n, _, _ := f.c.KV().Get(f.ctx, cache.RateKey("fail", "u1")); n != "2" {
		t.Fatalf("failures counted %q", n)
	}
	// Removal confirmed with a recovery code.
	if err := f.svc.Remove(f.ctx, f.alice, reg.Key.ID, Confirmation{Code: reg.RecoveryCodes[0]}); err != nil {
		t.Fatal(err)
	}
	if len(f.keys(t, f.alice)) != 1 {
		t.Fatal("not removed")
	}
	// The last key goes after a key assertion; the tenant does not require
	// MFA, so the second step and the codes go with it.
	if err := f.svc.Remove(f.ctx, f.alice, reg2.Key.ID, Confirmation{Credential: f.stepUp(t, f.alice, travel)}); err != nil {
		t.Fatal(err)
	}
	u, _ := f.ms.User(f.ctx, tA, "u1")
	codes, _ := f.ms.ListRecoveryCodeHashes(f.ctx, tA, "u1")
	if u.MFAEnabled || len(codes) != 0 || len(f.keys(t, f.alice)) != 0 {
		t.Fatalf("%+v %d", u, len(codes))
	}
	if a := f.auditTypes(); !strings.Contains(a, `mfa_removed:ok:{"method":"webauthn"}`) || !strings.Contains(a, `mfa_removed:refused:{"method":"webauthn"}`) {
		t.Fatalf("audit %s", a)
	}
	// Required policy: the only key stays until another factor exists.
	opKey := softkey.New(origin)
	regOp := f.register(t, f.op, opKey, "Only")
	if err := f.svc.Remove(f.ctx, f.op, regOp.Key.ID, Confirmation{Credential: f.stepUp(t, f.op, opKey)}); !errors.Is(err, ErrLastFactor) {
		t.Fatalf("last factor: %v", err)
	}
}

// Wrong confirmations share the sign-in lockout.
func TestRemovalLockout(t *testing.T) {
	f := setup(t, "preferred")
	desk := softkey.New(origin)
	reg := f.register(t, f.alice, desk, "Desk")
	f.register(t, f.alice, softkey.New(origin), "Spare")
	evil := *desk
	evil.Origin = "https://evil.example.org"
	for i := 0; i < 3; i++ {
		if err := f.svc.Remove(f.ctx, f.alice, reg.Key.ID, Confirmation{Credential: f.stepUp(t, f.alice, &evil)}); !errors.Is(err, ErrConfirmationFailed) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if locked, _ := f.c.Locked(f.ctx, "u1"); !locked {
		t.Fatal("threshold reached, account must be locked")
	}
	if err := f.svc.Remove(f.ctx, f.alice, reg.Key.ID, Confirmation{Code: reg.RecoveryCodes[0]}); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
	if a := f.auditTypes(); !strings.Contains(a, "lockout:refused") {
		t.Fatalf("audit %s", a)
	}
}

func TestNewRefusesBadRelyingParty(t *testing.T) {
	if _, err := New(Config{RPID: "auth.example.org", DisplayName: "T", UserVerification: "preferred", Timeout: time.Minute}, nil, nil, nil, nil); err == nil {
		t.Fatal("no origins accepted")
	}
	s, err := New(Config{RPID: rpID, Origins: []string{origin}, DisplayName: "T", UserVerification: "required", Timeout: time.Minute}, nil, nil, nil, nil)
	if err != nil || s.ttl != time.Minute {
		t.Fatal(err)
	}
	s.emit(audit.Event{}) // no writer: nothing happens
}

func TestFailurePaths(t *testing.T) {
	f := setup(t, "preferred")
	desk := softkey.New(origin)
	reg := f.register(t, f.alice, desk, "Desk")
	f.register(t, f.alice, softkey.New(origin), "Spare")
	// BeginRegistration.
	for _, fl := range []string{"user", "list", "ensure"} {
		f.fs.fail[fl] = true
		if _, err := f.svc.BeginRegistration(f.ctx, f.alice, "New"); !errors.Is(err, errDown) {
			t.Errorf("begin with %s failure: %v", fl, err)
		}
		f.fs.fail[fl] = false
	}
	restore := crypto.SetRand(errReader{})
	if _, err := f.svc.BeginRegistration(f.ctx, f.alice, "New"); err == nil {
		t.Error("begin without entropy")
	}
	restore()
	f.kv.set = true
	if _, err := f.svc.BeginRegistration(f.ctx, f.alice, "New"); !errors.Is(err, errDown) {
		t.Error("begin with cache failure")
	}
	if _, err := f.svc.StepUpOptions(f.ctx, f.alice); !errors.Is(err, errDown) {
		t.Error("step-up with cache failure")
	}
	f.kv.set = false
	_, _ = f.ms.EnsureWebAuthnHandle(f.ctx, tA, "u2", make([]byte, 100)) // not a valid user handle
	if _, err := f.svc.BeginRegistration(f.ctx, f.bob, "New"); err == nil {
		t.Error("library refusal of the user handle")
	}
	// FinishRegistration.
	for _, fl := range []string{"user", "handle", "list", "insert"} {
		resp, _ := softkey.New(origin).Create(f.begin(t, f.alice, "New"))
		f.fs.fail[fl] = true
		if _, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); !errors.Is(err, errDown) {
			t.Errorf("finish with %s failure: %v", fl, err)
		}
		f.fs.fail[fl] = false
	}
	resp, _ := softkey.New(origin).Create(f.begin(t, f.alice, "New"))
	f.ff.fail["added"] = true
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); !errors.Is(err, errDown) {
		t.Error("finish with factor failure")
	}
	f.ff.fail["added"] = false
	f.begin(t, f.alice, "Newer")
	f.kv.getdel = true
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); !errors.Is(err, ErrRegistrationFailed) {
		t.Error("finish with cache failure")
	}
	f.kv.getdel = false
	// Assertions.
	for _, fl := range []string{"user", "handle", "list"} {
		f.fs.fail[fl] = true
		if _, err := f.svc.SigninOptions(f.ctx, "r", tA, "u1"); !errors.Is(err, errDown) {
			t.Errorf("options with %s failure: %v", fl, err)
		}
		f.fs.fail[fl] = false
	}
	for _, fl := range []string{"user", "handle", "list", "use"} {
		resp := f.signinResponse(t, "r", f.alice, desk)
		f.fs.fail[fl] = true
		if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", resp); !errors.Is(err, errDown) {
			t.Errorf("verify with %s failure: %v", fl, err)
		}
		f.fs.fail[fl] = false
	}
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", f.signinResponse(t, "r", f.alice, desk)); err != nil {
		t.Fatal(err)
	}
	clone := *desk
	clone.Counter = 0
	resp = f.signinResponse(t, "r", f.alice, &clone)
	f.fs.fail["flag"] = true
	if err := f.svc.VerifySignin(f.ctx, "r", tA, "u1", resp); !errors.Is(err, errDown) {
		t.Errorf("flag failure: %v", err)
	}
	f.fs.fail["flag"] = false
	// Rename.
	f.fs.fail["rename"] = true
	if _, err := f.svc.Rename(f.ctx, f.alice, reg.Key.ID, "X"); !errors.Is(err, errDown) {
		t.Error("rename failure")
	}
	f.fs.fail["rename"] = false
	f.fs.fail["list"] = true
	if _, err := f.svc.Rename(f.ctx, f.alice, reg.Key.ID, "X"); !errors.Is(err, errDown) {
		t.Error("rename list failure")
	}
	f.fs.fail["list"] = false
	f.fs.fail["empty"] = true
	if _, err := f.svc.Rename(f.ctx, f.alice, reg.Key.ID, "Y"); !errors.Is(err, ErrNotFound) {
		t.Error("renamed key gone meanwhile")
	}
	f.fs.fail["empty"] = false
	// A corrupt ceremony record is a missing one.
	_ = f.kv.Memory.Set(f.ctx, cache.WebAuthnKey("reg", "u1"), "garbage", time.Minute)
	if _, err := f.svc.FinishRegistration(f.ctx, f.alice, resp); !errors.Is(err, ErrRegistrationFailed) {
		t.Error("corrupt record")
	}
	// Remove.
	f.fs.fail["delete"] = true
	if err := f.svc.Remove(f.ctx, f.alice, reg.Key.ID, Confirmation{Code: reg.RecoveryCodes[1]}); !errors.Is(err, errDown) {
		t.Error("delete failure")
	}
	f.fs.fail["delete"] = false
	f.ff.fail["removed"] = true
	if err := f.svc.Remove(f.ctx, f.alice, reg.Key.ID, Confirmation{Code: reg.RecoveryCodes[2]}); !errors.Is(err, errDown) {
		t.Error("factor failure on remove")
	}
	f.ff.fail["removed"] = false
	spare := f.keys(t, f.alice)[0]
	f.ms.Tenants[tA] = store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")}
	svc2, _ := New(f.cfg, f.fs, guardErr{f.ff}, f.c, nil)
	if err := svc2.Remove(f.ctx, f.alice, spare.ID, Confirmation{}); !errors.Is(err, errDown) {
		t.Errorf("guard failure: %v", err)
	}
	// The failure counter falls back to the default policy when the tenant
	// cannot be read or parsed.
	f.fs.fail["tenant"] = true
	if err := f.svc.Remove(f.ctx, f.alice, spare.ID, Confirmation{Code: "bad"}); !errors.Is(err, ErrConfirmationFailed) {
		t.Errorf("tenant failure: %v", err)
	}
	f.fs.fail["tenant"] = false
	f.ms.Tenants[tA] = store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("nope")}
	f.svc.failed(f.ctx, f.alice)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errDown }

type guardErr struct{ *failFactors }

func (guardErr) GuardRemoval(context.Context, string, string, string) error { return errDown }

func TestView(t *testing.T) {
	now := time.Now()
	k := View(store.WebAuthnCredential{ID: "k", Name: "n", CreatedAt: now, LastUsedAt: &now, CloneFlaggedAt: &now, CredentialID: []byte{1}, PublicKey: []byte{2}})
	b, _ := json.Marshal(k)
	if !k.Flagged || k.LastUsedAt == nil || strings.Contains(string(b), "public") || strings.Contains(string(b), "credential") {
		t.Fatalf("%s", b)
	}
}
