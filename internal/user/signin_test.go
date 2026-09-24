package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
)

type fakeMFA struct{ good string }

func (f fakeMFA) Verify(_ context.Context, _, _ string, code string) (string, error) {
	if code == f.good {
		return "otp", nil
	}
	return "", errors.New("bad code")
}

func setup(t *testing.T) (*Service, *memstore.Store, *cache.Cache) {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte(`{"lockout_threshold":3,"lockout_duration":"5m"}`)})
	ms.AddTenant(store.Tenant{ID: tB, Slug: "frozen", Status: "suspended", Kind: "customer", Policy: []byte("{}")})
	h, _ := password.Hash("correct horse battery")
	ms.AddUser(store.User{ID: "u1", TenantID: tA, Email: "alice@x.test", Status: "active", PasswordHash: &h})
	ms.AddUser(store.User{ID: "u2", TenantID: tA, Email: "mfa@x.test", Status: "active", PasswordHash: &h, MFAEnabled: true})
	ms.AddUser(store.User{ID: "u3", TenantID: tA, Email: "gone@x.test", Status: "deactivated", PasswordHash: &h})
	ms.AddUser(store.User{ID: "u4", TenantID: tA, Email: "new@x.test", Status: "invited"})
	ms.AddUser(store.User{ID: "u5", TenantID: tB, Email: "alice@x.test", Status: "active", PasswordHash: &h})
	ms.SetRoles(tA, "u1", []string{"admin"})
	c := cache.New(cache.NewMemory())
	sm := session.New(ms, c, nil)
	svc := New(ms, c, nil, sm, fakeMFA{good: "123456"})
	svc.pad = func(time.Time) {}
	return svc, ms, c
}

func TestSigninMatrix(t *testing.T) {
	svc, ms, _ := setup(t)
	ctx := context.Background()
	good := Input{TenantSlug: "acme", Email: "Alice@X.test", Password: "correct horse battery", IP: "203.0.113.1", UserAgent: "ua"}
	res, err := svc.Start(ctx, good)
	if err != nil || res.Secret == "" || res.Session.UserID != "u1" || res.Roles[0] != "admin" || res.MFARequired {
		t.Fatalf("%+v %v", res, err)
	}
	if last := ms.Attempts[len(ms.Attempts)-1]; last.Outcome != "ok" || last.UserID != "u1" {
		t.Fatalf("attempt %+v", last)
	}
	// Every failure mode is the same refusal.
	for name, in := range map[string]Input{
		"unknown tenant":   {TenantSlug: "nope", Email: "alice@x.test", Password: "correct horse battery", IP: "1"},
		"bad slug":         {TenantSlug: "Not Valid", Email: "alice@x.test", Password: "correct horse battery", IP: "1"},
		"unknown email":    {TenantSlug: "acme", Email: "bob@x.test", Password: "correct horse battery", IP: "1"},
		"wrong password":   {TenantSlug: "acme", Email: "alice@x.test", Password: "wrong", IP: "1"},
		"suspended tenant": {TenantSlug: "frozen", Email: "alice@x.test", Password: "correct horse battery", IP: "1"},
		"deactivated":      {TenantSlug: "acme", Email: "gone@x.test", Password: "correct horse battery", IP: "1"},
		"invited":          {TenantSlug: "acme", Email: "new@x.test", Password: "anything", IP: "1"},
		"empty":            {},
	} {
		if _, err := svc.Start(ctx, in); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// No tenant given: it is taken from the email domain (x.test → "x").
	ms.AddTenant(store.Tenant{ID: "t-x", Slug: "x", Status: "active", Kind: "customer", Policy: []byte("{}")})
	h, _ := password.Hash("correct horse battery")
	ms.AddUser(store.User{ID: "u6", TenantID: "t-x", Email: "carol@x.test", Status: "active", PasswordHash: &h})
	if res, err := svc.Start(ctx, Input{Email: "Carol@X.test", Password: "correct horse battery", IP: "3"}); err != nil || res.Session.UserID != "u6" {
		t.Fatalf("tenant from email domain: %+v %v", res, err)
	}
	// An explicit tenant still wins over the domain, and a domain without a
	// matching tenant is the same refusal as any other failure.
	if res, err := svc.Start(ctx, Input{TenantSlug: "acme", Email: "alice@x.test", Password: "correct horse battery", IP: "3"}); err != nil || res.Session.UserID != "u1" {
		t.Fatalf("explicit tenant: %+v %v", res, err)
	}
	for _, e := range []string{"dave@nowhere.test", "carol@", "carol"} {
		if _, err := svc.Start(ctx, Input{Email: e, Password: "correct horse battery", IP: "3"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: %v", e, err)
		}
	}
	// Same email in another tenant is a separate account.
	if _, err := svc.Start(ctx, Input{TenantSlug: "acme", Email: "alice@x.test", Password: "correct horse battery", IP: "2"}); err != nil {
		t.Fatal(err)
	}
}

func TestLockoutAndRateLimits(t *testing.T) {
	svc, ms, c := setup(t)
	ctx := context.Background()
	bad := Input{TenantSlug: "acme", Email: "alice@x.test", Password: "wrong", IP: "9"}
	for i := 0; i < 3; i++ {
		if _, err := svc.Start(ctx, bad); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatal(err)
		}
	}
	if locked, _ := c.Locked(ctx, "u1"); !locked {
		t.Fatal("threshold must lock")
	}
	good := Input{TenantSlug: "acme", Email: "alice@x.test", Password: "correct horse battery", IP: "9"}
	if _, err := svc.Start(ctx, good); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked account must refuse even the right password: %v", err)
	}
	if last := ms.Attempts[len(ms.Attempts)-1]; last.Reason != "locked" {
		t.Fatalf("%+v", last)
	}
	_ = c.Unlock(ctx, "u1")
	if _, err := svc.Start(ctx, good); err != nil {
		t.Fatal("unlock")
	}
	// Per-origin limit.
	for i := 0; i < IPLimit; i++ {
		_, _ = svc.Start(ctx, Input{TenantSlug: "acme", Email: "nobody@x.test", Password: "x", IP: "flood"})
	}
	if _, err := svc.Start(ctx, Input{TenantSlug: "acme", Email: "alice@x.test", Password: "correct horse battery", IP: "flood"}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("ip limit: %v", err)
	}
	// Per-account limit from many origins.
	for i := 0; i < AccountLimit; i++ {
		_, _ = svc.Start(ctx, Input{TenantSlug: "acme", Email: "mfa@x.test", Password: "x", IP: string(rune('a' + i))})
	}
	if _, err := svc.Start(ctx, Input{TenantSlug: "acme", Email: "mfa@x.test", Password: "correct horse battery", IP: "zz"}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("account limit: %v", err)
	}
}

func TestMFAHandOff(t *testing.T) {
	svc, _, c := setup(t)
	ctx := context.Background()
	res, err := svc.Start(ctx, Input{TenantSlug: "acme", Email: "mfa@x.test", Password: "correct horse battery", IP: "3", UserAgent: "ua"})
	if err != nil || !res.MFARequired || res.Challenge == "" || res.Secret != "" {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := svc.CompleteMFA(ctx, res.Challenge, "000000", "3", "ua"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("wrong code accepted")
	}
	if _, err := svc.CompleteMFA(ctx, "nope", "123456", "3", "ua"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("unknown challenge accepted")
	}
	done, err := svc.CompleteMFA(ctx, res.Challenge, "123456", "3", "ua")
	if err != nil || done.Secret == "" || len(done.Session.AMR) != 2 || done.Session.AMR[1] != "otp" {
		t.Fatalf("%+v %v", done, err)
	}
	if _, err := svc.CompleteMFA(ctx, res.Challenge, "123456", "3", "ua"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("challenge must be single-use")
	}
	// Repeated MFA failures lock the account too.
	res, _ = svc.Start(ctx, Input{TenantSlug: "acme", Email: "mfa@x.test", Password: "correct horse battery", IP: "3"})
	for i := 0; i < 3; i++ {
		_, _ = svc.CompleteMFA(ctx, res.Challenge, "000000", "3", "ua")
	}
	if locked, _ := c.Locked(ctx, "u2"); !locked {
		t.Fatal("mfa failures must lock")
	}
	// No verifier configured: challenges can never complete.
	svc.SetMFA(nil)
	_ = c.Unlock(ctx, "u2")
	res, _ = svc.Start(ctx, Input{TenantSlug: "acme", Email: "mfa@x.test", Password: "correct horse battery", IP: "4"})
	if _, err := svc.CompleteMFA(ctx, res.Challenge, "123456", "4", "ua"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
}

// TestImportedIsUnknown (feature 016, SR-006/SC-002): an account imported from
// a directory but never activated is indistinguishable from one that does not
// exist — same refusal, same audit reason, no lockout counter, never locked,
// and the dummy hash is verified rather than anything stored on the row.
func TestImportedIsUnknown(t *testing.T) {
	svc, ms, c := setup(t)
	ctx := context.Background()
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	svc.audit = aw
	ms.AddUser(store.User{ID: "u-imp", TenantID: tA, Email: "imported@x.test", Status: "imported"})
	// A stray hash on an imported row must never be what gets verified.
	h, _ := password.Hash("correct horse battery")
	ms.AddUser(store.User{ID: "u-imp-hash", TenantID: tA, Email: "imported-hash@x.test", Status: "imported", PasswordHash: &h})

	type observed struct {
		err     error
		attempt memstore.Attempt
	}
	try := func(email, pw, ip string) observed {
		t.Helper()
		_, err := svc.Start(ctx, Input{TenantSlug: "acme", Email: email, Password: pw, IP: ip, UserAgent: "ua"})
		return observed{err: err, attempt: ms.Attempts[len(ms.Attempts)-1]}
	}
	unknown := try("ghost@x.test", "wrong", "10")
	if !errors.Is(unknown.err, ErrInvalidCredentials) || unknown.attempt.Reason != "unknown_account" || unknown.attempt.UserID != "" {
		t.Fatalf("baseline unknown: %+v", unknown)
	}
	for _, email := range []string{"imported@x.test", "Imported-Hash@X.test"} {
		for _, pw := range []string{"wrong", "correct horse battery"} {
			got := try(email, pw, "11")
			if !errors.Is(got.err, ErrInvalidCredentials) {
				t.Fatalf("%s/%s: %v", email, pw, got.err)
			}
			if got.attempt.Reason != unknown.attempt.Reason || got.attempt.Outcome != unknown.attempt.Outcome || got.attempt.UserID != "" || got.attempt.TenantID != tA {
				t.Fatalf("%s: attempt %+v differs from unknown %+v", email, got.attempt, unknown.attempt)
			}
		}
	}
	// Ten wrong passwords (threshold is 3): no counter, no lock, no 423 oracle.
	for i := 0; i < 10; i++ {
		if got := try("imported@x.test", "wrong", "12"); !errors.Is(got.err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, got.err)
		}
	}
	for _, uid := range []string{"u-imp", "u-imp-hash"} {
		if _, ok, _ := c.KV().Get(ctx, cache.RateKey("fail", uid)); ok {
			t.Fatalf("%s: lockout counter created", uid)
		}
		if locked, _ := c.Locked(ctx, uid); locked {
			t.Fatalf("%s: imported account locked", uid)
		}
	}
	if got := try("imported@x.test", "anything", "12"); errors.Is(got.err, ErrLocked) || got.attempt.Reason == "locked" {
		t.Fatalf("imported account reported locked: %+v", got)
	}
	aw.Flush()
	for _, r := range ms.AuditRows {
		if r.EventType == string(audit.Lockout) {
			t.Fatalf("lockout audited: %+v", r)
		}
		if r.EventType != string(audit.SigninFailed) {
			continue
		}
		if r.ActorUserID != nil || r.Reason != "unknown_account" {
			t.Fatalf("signin failure must look like an unknown account: reason=%q actor=%v", r.Reason, r.ActorUserID)
		}
	}
	// The dummy verify runs: an imported account costs the same hash work as
	// an unknown one (pad disabled, so only the verify is measured).
	cost := func(email string) time.Duration {
		best := time.Duration(1 << 62)
		for i := 0; i < 3; i++ {
			start := time.Now()
			_, _ = svc.Start(ctx, Input{TenantSlug: "acme", Email: email, Password: "wrong", IP: "13"})
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}
	if ratio := float64(cost("imported@x.test")) / float64(cost("ghost@x.test")); ratio < 0.5 || ratio > 2 {
		t.Fatalf("imported path skips or adds hash work: ratio %.2f", ratio)
	}
}
