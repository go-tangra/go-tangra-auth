package mfa

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Feature 018: factors of any kind share recovery codes and the
// "asks for a second step" flag.

func addKey(t *testing.T, ms *failing, tid, uid, name string, flagged bool) store.WebAuthnCredential {
	t.Helper()
	k := store.WebAuthnCredential{ID: store.NewID(), TenantID: tid, UserID: uid, CredentialID: bytes.Repeat([]byte(name), 16), PublicKey: []byte{1}, Name: name}
	if err := ms.InsertWebAuthnCredential(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	if flagged {
		_ = ms.FlagWebAuthnClone(context.Background(), tid, k.ID)
	}
	return k
}

func TestKeyFirstFactorIssuesCodes(t *testing.T) {
	svc, ms, _ := setup(t)
	ctx := context.Background()
	alice := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tA}
	fs := &failing{Store: ms, fail: map[string]bool{}}
	svc.st = fs
	st, err := svc.State(ctx, tA, "u1")
	if err != nil || st.TOTP || len(st.Keys) != 0 || st.RecoveryCodesLeft != 0 || st.Required || st.Enabled {
		t.Fatalf("%+v %v", st, err)
	}
	if m, _ := svc.Methods(ctx, tA, "u1"); len(m) != 0 {
		t.Fatalf("methods %v", m)
	}
	// First key: the account asks for a second step and gets ten codes.
	k1 := addKey(t, fs, tA, "u1", "desk", false)
	codes, err := svc.KeyAdded(ctx, alice)
	if err != nil || len(codes) != RecoveryCount {
		t.Fatalf("%v %v", codes, err)
	}
	if u, _ := ms.User(ctx, tA, "u1"); !u.MFAEnabled || u.MFASecretEnc != nil {
		t.Fatalf("%+v", u)
	}
	// Second key: codes stay as they are.
	addKey(t, fs, tA, "u1", "travel", false)
	if again, err := svc.KeyAdded(ctx, alice); err != nil || again != nil {
		t.Fatalf("second key replaced codes: %v %v", again, err)
	}
	if m, err := svc.Verify(ctx, tA, "u1", codes[0]); err != nil || m != "recovery" {
		t.Fatalf("recovery code of the first key must still work: %v %v", m, err)
	}
	// A key-only user has no authenticator app: digits are never a valid code.
	if _, err := svc.Verify(ctx, tA, "u1", "123456"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("totp without seed: %v", err)
	}
	st, _ = svc.State(ctx, tA, "u1")
	if !st.Enabled || st.TOTP || len(st.Keys) != 2 || st.RecoveryCodesLeft != RecoveryCount-1 || st.Usable() != 2 || st.Keys[0].ID != k1.ID || st.Keys[0].Name != "desk" || st.Keys[0].Flagged {
		t.Fatalf("%+v", st)
	}
	if m, _ := svc.Methods(ctx, tA, "u1"); !slices.Equal(m, []string{"webauthn", "recovery"}) {
		t.Fatalf("methods %v", m)
	}
	// Adding TOTP later keeps the codes (not the first factor).
	enr, _ := svc.Enrol(ctx, alice)
	now := svc.now()
	more, err := svc.Confirm(ctx, alice, code(enr.Secret, now))
	if err != nil || more != nil {
		t.Fatalf("totp as second factor replaced codes: %v %v", more, err)
	}
	if m, _ := svc.Methods(ctx, tA, "u1"); !slices.Equal(m, []string{"webauthn", "totp", "recovery"}) {
		t.Fatalf("methods %v", m)
	}
	if st, _ := svc.State(ctx, tA, "u1"); st.Usable() != 3 || !st.TOTP {
		t.Fatalf("%+v", st)
	}
	// Disabling TOTP while keys remain keeps the second step and the codes.
	svc.now = func() time.Time { return now.Add(30 * time.Second) }
	if err := svc.Disable(ctx, alice, code(enr.Secret, svc.now())); err != nil {
		t.Fatal(err)
	}
	u, _ := ms.User(ctx, tA, "u1")
	if !u.MFAEnabled || u.MFASecretEnc != nil {
		t.Fatalf("keys remain: %+v", u)
	}
	if h, _ := ms.ListRecoveryCodeHashes(ctx, tA, "u1"); len(h) != RecoveryCount-1 {
		t.Fatalf("codes dropped with keys left: %d", len(h))
	}
	// Flagged keys are listed but are not a usable method.
	for _, k := range st.Keys {
		_ = ms.FlagWebAuthnClone(ctx, tA, k.ID)
	}
	if m, _ := svc.Methods(ctx, tA, "u1"); !slices.Equal(m, []string{"recovery"}) {
		t.Fatalf("methods %v", m)
	}
	if st, _ := svc.State(ctx, tA, "u1"); st.Usable() != 0 || !st.Keys[0].Flagged {
		t.Fatalf("%+v", st)
	}
}

func TestTOTPFirstThenKeyKeepsCodes(t *testing.T) {
	svc, ms, now := setup(t)
	ctx := context.Background()
	alice := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tA}
	enr, _ := svc.Enrol(ctx, alice)
	codes, err := svc.Confirm(ctx, alice, code(enr.Secret, *now))
	if err != nil || len(codes) != RecoveryCount {
		t.Fatal(codes, err)
	}
	addKey(t, &failing{Store: ms}, tA, "u1", "desk", false)
	if more, err := svc.KeyAdded(ctx, alice); err != nil || more != nil {
		t.Fatalf("key after totp replaced codes: %v %v", more, err)
	}
	if m, err := svc.Verify(ctx, tA, "u1", codes[3]); err != nil || m != "recovery" {
		t.Fatal(m, err)
	}
}

func TestKeyRemovedAndGuard(t *testing.T) {
	svc, ms, _ := setup(t)
	ctx := context.Background()
	alice := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tA}
	fs := &failing{Store: ms, fail: map[string]bool{}}
	svc.st = fs
	k := addKey(t, fs, tA, "u1", "desk", false)
	if _, err := svc.KeyAdded(ctx, alice); err != nil {
		t.Fatal(err)
	}
	// Optional policy: the last key may go; the account stops asking and
	// the unused codes are invalidated.
	if err := svc.GuardRemoval(ctx, tA, "u1", k.ID); err != nil {
		t.Fatal(err)
	}
	_ = ms.DeleteWebAuthnCredential(ctx, tA, "u1", k.ID)
	if err := svc.KeyRemoved(ctx, alice); err != nil {
		t.Fatal(err)
	}
	u, _ := ms.User(ctx, tA, "u1")
	if h, _ := ms.ListRecoveryCodeHashes(ctx, tA, "u1"); u.MFAEnabled || len(h) != 0 {
		t.Fatalf("%+v codes %d", u, len(h))
	}
	// Other factors left: nothing changes.
	k1 := addKey(t, fs, tA, "u1", "one", false)
	addKey(t, fs, tA, "u1", "two", false)
	_, _ = svc.KeyAdded(ctx, alice)
	_ = ms.DeleteWebAuthnCredential(ctx, tA, "u1", k1.ID)
	if err := svc.KeyRemoved(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if u, _ := ms.User(ctx, tA, "u1"); !u.MFAEnabled {
		t.Fatal("second step dropped while a key remains")
	}
	// Required policy (platform tenant): the last usable factor stays; a
	// flagged key can always go.
	op := tenantctx.Actor{Kind: tenantctx.KindOperator, UserID: "op", TenantID: tP}
	only := addKey(t, fs, tP, "op", "only", false)
	bad := addKey(t, fs, tP, "op", "cloned", true)
	_, _ = svc.KeyAdded(ctx, op)
	if st, _ := svc.State(ctx, tP, "op"); !st.Required {
		t.Fatal("platform tenant requires mfa")
	}
	if err := svc.GuardRemoval(ctx, tP, "op", only.ID); !errors.Is(err, ErrRequired) {
		t.Fatalf("last usable factor removed under policy: %v", err)
	}
	if err := svc.GuardRemoval(ctx, tP, "op", bad.ID); err != nil {
		t.Fatalf("flagged key must be removable: %v", err)
	}
	if err := svc.GuardRemoval(ctx, tP, "op", "unknown"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
	addKey(t, fs, tP, "op", "spare", false)
	if err := svc.GuardRemoval(ctx, tP, "op", only.ID); err != nil {
		t.Fatalf("a spare key exists: %v", err)
	}
}

func TestFactorFailurePaths(t *testing.T) {
	svc, ms, now := setup(t)
	ctx := context.Background()
	fs := &failing{Store: ms, fail: map[string]bool{}}
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	svc = New(fs, cache.New(cache.NewMemory()), svc.env, aw, "Tangra")
	svc.now = func() time.Time { return *now }
	alice := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tA}
	for _, f := range []string{"user", "tenant", "keys", "list"} {
		fs.fail[f] = true
		if _, err := svc.State(ctx, tA, "u1"); !errors.Is(err, errDown) {
			t.Fatalf("state with %s failure: %v", f, err)
		}
		if _, err := svc.Methods(ctx, tA, "u1"); !errors.Is(err, errDown) {
			t.Fatalf("methods with %s failure: %v", f, err)
		}
		if err := svc.GuardRemoval(ctx, tA, "u1", "k"); !errors.Is(err, errDown) {
			t.Fatalf("guard with %s failure: %v", f, err)
		}
		fs.fail[f] = false
	}
	tn := ms.Tenants[tA]
	tn.Policy = []byte("nope")
	ms.AddTenant(tn)
	if _, err := svc.State(ctx, tA, "u1"); err == nil {
		t.Fatal("bad policy")
	}
	tn.Policy = []byte("{}")
	ms.AddTenant(tn)
	for _, f := range []string{"user", "keys", "setMFA", "replace"} {
		fs.fail[f] = true
		if _, err := svc.KeyAdded(ctx, alice); !errors.Is(err, errDown) {
			t.Fatalf("key added with %s failure: %v", f, err)
		}
		fs.fail[f] = false
	}
	for _, f := range []string{"user", "keys", "setMFA", "replace"} {
		_ = ms.SetMFA(ctx, tA, "u1", true, nil)
		fs.fail[f] = true
		if err := svc.KeyRemoved(ctx, alice); !errors.Is(err, errDown) {
			t.Fatalf("key removed with %s failure: %v", f, err)
		}
		fs.fail[f] = false
	}
	// TOTP paths that look at keys.
	_ = ms.SetMFA(ctx, tA, "u1", false, nil)
	enr, _ := svc.Enrol(ctx, alice)
	fs.fail["keys"] = true
	if _, err := svc.Confirm(ctx, alice, code(enr.Secret, *now)); !errors.Is(err, errDown) {
		t.Fatalf("confirm with keys failure: %v", err)
	}
	fs.fail["keys"] = false
	enr, _ = svc.Enrol(ctx, alice)
	if _, err := svc.Confirm(ctx, alice, code(enr.Secret, *now)); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(30 * time.Second)
	fs.fail["keys"] = true
	if err := svc.Disable(ctx, alice, code(enr.Secret, *now)); !errors.Is(err, errDown) {
		t.Fatalf("disable with keys failure: %v", err)
	}
	fs.fail["keys"] = false
	addKey(t, fs, tA, "u1", "desk", false)
	fs.fail["setMFA"] = true
	if err := svc.Disable(ctx, alice, code(enr.Secret, *now)); !errors.Is(err, errDown) {
		t.Fatalf("disable keeping keys with setMFA failure: %v", err)
	}
	fs.fail["setMFA"] = false
}

// Under a required policy the app may go while a usable key remains; a
// flagged key does not count.
func TestDisableTOTPUnderPolicyWithKeys(t *testing.T) {
	svc, ms, now := setup(t)
	ctx := context.Background()
	op := tenantctx.Actor{Kind: tenantctx.KindOperator, UserID: "op", TenantID: tP}
	fs := &failing{Store: ms, fail: map[string]bool{}}
	enr, _ := svc.Enrol(ctx, op)
	if _, err := svc.Confirm(ctx, op, code(enr.Secret, *now)); err != nil {
		t.Fatal(err)
	}
	bad := addKey(t, fs, tP, "op", "cloned", true)
	*now = now.Add(30 * time.Second)
	if err := svc.Disable(ctx, op, code(enr.Secret, *now)); !errors.Is(err, ErrRequired) {
		t.Fatalf("only a flagged key left: %v", err)
	}
	_ = ms.DeleteWebAuthnCredential(ctx, tP, "op", bad.ID)
	addKey(t, fs, tP, "op", "good", false)
	if err := svc.Disable(ctx, op, code(enr.Secret, *now)); err != nil {
		t.Fatalf("a usable key remains: %v", err)
	}
	if st, _ := svc.State(ctx, tP, "op"); st.TOTP || !st.Enabled || st.RecoveryCodesLeft != RecoveryCount {
		t.Fatalf("%+v", st)
	}
}
