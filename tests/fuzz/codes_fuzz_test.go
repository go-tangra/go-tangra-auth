package fuzz

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/email"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/mfa"
	"github.com/go-freya/freya/services/auth/internal/password"
	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

type sink struct{}

func (sink) Send(context.Context, email.Message) error { return nil }

func mfaFixture(f *testing.F) (*mfa.Service, string, []string) {
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tid, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u1", TenantID: tid, Email: "a@x.test", Status: "active"})
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{3}, 32))
	svc := mfa.New(ms, cache.New(cache.NewMemory()), env, nil, "Freya")
	actor := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tid}
	enr, err := svc.Enrol(context.Background(), actor)
	if err != nil {
		f.Fatal(err)
	}
	code, _ := totp.GenerateCode(enr.Secret, time.Now())
	codes, err := svc.Confirm(context.Background(), actor, code)
	if err != nil {
		f.Fatal(err)
	}
	return svc, enr.Secret, codes
}

func FuzzTOTPCode(f *testing.F) {
	svc, secret, _ := mfaFixture(f)
	for _, s := range []string{"000000", "123456", "", "12345", "1234567", "abcdef", "١٢٣٤٥٦"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, code string) {
		m, err := svc.Verify(context.Background(), tid, "u1", code)
		if err == nil {
			// Only a genuine, unused step may pass.
			now, _ := totp.GenerateCode(secret, time.Now())
			prev, _ := totp.GenerateCode(secret, time.Now().Add(-30*time.Second))
			next, _ := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
			if m != "otp" || (code != now && code != prev && code != next) {
				t.Fatalf("code %q accepted", code)
			}
		}
	})
}

func FuzzRecoveryCode(f *testing.F) {
	svc, _, codes := mfaFixture(f)
	for _, s := range []string{codes[0], "abcde-fghjk", "", "ZZZZZ-ZZZZZ", "ABCDE FGHJK", "ABCDEFGHJK1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, code string) {
		norm := mfa.NormalizeRecovery(code)
		if norm != "" && len(norm) != 10 {
			t.Fatalf("normalized %q has wrong length", norm)
		}
		m, err := svc.Verify(context.Background(), tid, "u1", code)
		if err == nil && m != "recovery" && m != "otp" {
			t.Fatalf("unexpected method %q", m)
		}
	})
}

func FuzzRecoveryToken(f *testing.F) {
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tid, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{4}, 32))
	rec := password.NewRecovery(ms, email.NewOutbox(env, sink{}, nil, 3, nil), session.New(ms, cache.New(cache.NewMemory()), nil), nil, "https://auth.example.org")
	rec.SetPad(func(time.Time) {})
	for _, s := range []string{"", "AAAA", "not-a-token", "\x00\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		if err := rec.Complete(context.Background(), token, "a-long-enough-password"); err == nil {
			t.Fatalf("token %q accepted", token)
		}
	})
}
