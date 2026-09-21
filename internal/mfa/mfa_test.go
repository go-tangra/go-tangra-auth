package mfa

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tP = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
)

func setup(t *testing.T) (*Service, *memstore.Store, *time.Time) {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddTenant(store.Tenant{ID: tP, Slug: "platform", Status: "active", Kind: "platform", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u1", TenantID: tA, Email: "alice@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "op", TenantID: tP, Email: "ops@x.test", Status: "active"})
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{9}, 32))
	now := time.Date(2026, 9, 16, 12, 0, 5, 0, time.UTC)
	svc := New(ms, cache.New(cache.NewMemory()), env, nil, "Freya")
	svc.now = func() time.Time { return now }
	return svc, ms, &now
}

func code(secret string, at time.Time) string {
	c, _ := totp.GenerateCodeCustom(secret, at, opts)
	return c
}

func TestEnrolConfirmVerifyReplay(t *testing.T) {
	svc, ms, now := setup(t)
	ctx := context.Background()
	alice := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tA}
	enr, err := svc.Enrol(ctx, alice)
	if err != nil || !strings.HasPrefix(enr.URI, "otpauth://totp/Freya:alice@x.test?") || !strings.Contains(enr.URI, "secret="+enr.Secret) {
		t.Fatalf("%+v %v", enr, err)
	}
	if u, _ := ms.User(ctx, tA, "u1"); u.MFAEnabled {
		t.Fatal("enrolment must not enable before confirmation")
	}
	if _, err := svc.Confirm(ctx, alice, "000000"); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("wrong code confirmed")
	}
	if _, err := svc.Verify(ctx, tA, "u1", code(enr.Secret, *now)); !errors.Is(err, ErrNotEnrolled) {
		t.Fatal("verify before confirm")
	}
	codes, err := svc.Confirm(ctx, alice, code(enr.Secret, *now))
	if err != nil || len(codes) != RecoveryCount {
		t.Fatal(codes, err)
	}
	u, _ := ms.User(ctx, tA, "u1")
	if !u.MFAEnabled || bytes.Contains(u.MFASecretEnc, []byte(enr.Secret)) {
		t.Fatal("seed must be stored sealed")
	}
	if _, err := svc.Confirm(ctx, alice, code(enr.Secret, *now)); !errors.Is(err, ErrNoPending) {
		t.Fatal("pending enrolment must be consumed")
	}
	// The confirmation code's step is spent; the next step works; ±1 window.
	if _, err := svc.Verify(ctx, tA, "u1", code(enr.Secret, *now)); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("replay of the confirmation step accepted")
	}
	*now = now.Add(30 * time.Second)
	if m, err := svc.Verify(ctx, tA, "u1", code(enr.Secret, *now)); err != nil || m != "otp" {
		t.Fatal(m, err)
	}
	if _, err := svc.Verify(ctx, tA, "u1", code(enr.Secret, *now)); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("same counter replayed")
	}
	*now = now.Add(60 * time.Second)
	if m, err := svc.Verify(ctx, tA, "u1", code(enr.Secret, now.Add(-30*time.Second))); err != nil || m != "otp" {
		t.Fatalf("previous step within skew: %v", err)
	}
	*now = now.Add(90 * time.Second)
	if _, err := svc.Verify(ctx, tA, "u1", code(enr.Secret, now.Add(-90*time.Second))); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("code outside the window accepted")
	}
	for _, bad := range []string{"", "12345", "abcdef", "1234567"} {
		if _, err := svc.Verify(ctx, tA, "u1", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// Recovery codes: single use, tolerant input, wrong ones refused.
	if m, err := svc.Verify(ctx, tA, "u1", strings.ToLower(codes[0])); err != nil || m != "recovery" {
		t.Fatal(m, err)
	}
	if _, err := svc.Verify(ctx, tA, "u1", codes[0]); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("recovery code reused")
	}
	if _, err := svc.Verify(ctx, tA, "u1", "ZZZZZ-ZZZZZ"); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("unknown recovery code accepted")
	}
	// Regenerate needs a valid code and invalidates the old set.
	*now = now.Add(30 * time.Second)
	fresh, err := svc.Regenerate(ctx, alice, code(enr.Secret, *now))
	if err != nil || len(fresh) != RecoveryCount {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, tA, "u1", codes[1]); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("old code still valid")
	}
	// Disable requires a valid code; hashes are cleared.
	*now = now.Add(30 * time.Second)
	if err := svc.Disable(ctx, alice, "000000"); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("disable without code")
	}
	if err := svc.Disable(ctx, alice, code(enr.Secret, *now)); err != nil {
		t.Fatal(err)
	}
	if u, _ := ms.User(ctx, tA, "u1"); u.MFAEnabled || u.MFASecretEnc != nil {
		t.Fatal("not disabled")
	}
	if h, _ := ms.ListRecoveryCodeHashes(ctx, tA, "u1"); len(h) != 0 {
		t.Fatal("codes not cleared")
	}
}

func TestDisableRefusedUnderPolicy(t *testing.T) {
	svc, _, now := setup(t)
	ctx := context.Background()
	op := tenantctx.Actor{Kind: tenantctx.KindOperator, UserID: "op", TenantID: tP}
	enr, _ := svc.Enrol(ctx, op)
	if _, err := svc.Confirm(ctx, op, code(enr.Secret, *now)); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(30 * time.Second)
	if err := svc.Disable(ctx, op, code(enr.Secret, *now)); !errors.Is(err, ErrRequired) {
		t.Fatalf("platform tenant must keep MFA: %v", err)
	}
	if NormalizeRecovery(" ab cde-fghjk ") != "ABCDEFGHJK" || NormalizeRecovery("ABCDE-FGH1K") != "" || NormalizeRecovery("short") != "" {
		t.Fatal("normalize")
	}
}
