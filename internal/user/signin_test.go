package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/password"
	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/internal/store"
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
