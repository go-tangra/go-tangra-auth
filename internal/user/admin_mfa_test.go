package user

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Feature 018 (US4): an administrator resets a user's second factors with the
// privilege rules of deactivation.
func TestAdminResetMFA(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddTenant(store.Tenant{ID: tB, Slug: "globex", Status: "active", Kind: "customer", Policy: []byte("{}")})
	for _, r := range []store.Role{{ID: "r-owner", TenantID: tA, Slug: "owner"}, {ID: "r-admin", TenantID: tA, Slug: "admin"}, {ID: "r-member", TenantID: tA, Slug: "member"}} {
		ms.AddRole(r)
	}
	ms.AddUser(store.User{ID: "u-owner", TenantID: tA, Email: "owner@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "u-admin", TenantID: tA, Email: "admin@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "u-bob", TenantID: tA, Email: "bob@x.test", Status: "active", MFAEnabled: true, MFASecretEnc: []byte("sealed")})
	ms.AddUser(store.User{ID: "u-imp", TenantID: tA, Email: "imp@x.test", Status: "imported"})
	ms.AddUser(store.User{ID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77", TenantID: tB, Email: "eve@x.test", Status: "active"})
	_ = ms.ReplaceBindings(ctx, tA, "u-owner", "", []string{"r-owner"})
	_ = ms.ReplaceBindings(ctx, tA, "u-admin", "", []string{"r-admin"})
	_ = ms.ReplaceBindings(ctx, tA, "u-bob", "", []string{"r-member"})
	_ = ms.ReplaceRecoveryCodes(ctx, tA, "u-bob", []string{"h1", "h2"})
	_ = ms.InsertWebAuthnCredential(ctx, store.WebAuthnCredential{ID: "k1", TenantID: tA, UserID: "u-bob", CredentialID: []byte("0123456789abcdef"), Name: "Desk"})
	c := cache.New(cache.NewMemory())
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	sm := session.New(ms, c, aw)
	admin := NewAdmin(ms, sm, aw)
	owner := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", TenantID: tA, Roles: []string{"owner"}}
	adm := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-admin", TenantID: tA, Roles: []string{"admin"}}

	_, secret, _ := sm.Create(ctx, session.CreateParams{TenantID: tA, UserID: "u-bob", Policy: tenant.DefaultPolicy()})
	if err := admin.ResetMFA(ctx, adm, "u-bob"); err != nil {
		t.Fatal(err)
	}
	u, _ := ms.User(ctx, tA, "u-bob")
	codes, _ := ms.ListRecoveryCodeHashes(ctx, tA, "u-bob")
	keys, _ := ms.ListWebAuthnCredentials(ctx, tA, "u-bob")
	if u.MFAEnabled || u.MFASecretEnc != nil || len(codes) != 0 || len(keys) != 0 {
		t.Fatalf("%+v codes %d keys %d", u, len(codes), len(keys))
	}
	if _, err := sm.Resolve(ctx, secret); !errors.Is(err, session.ErrNoSession) {
		t.Fatal("sessions must end with the reset")
	}
	// Refusals: self, a more privileged target, imported, unknown, foreign.
	if err := admin.ResetMFA(ctx, adm, "u-admin"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("self: %v", err)
	}
	if err := admin.ResetMFA(ctx, adm, "u-owner"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("admin resets owner: %v", err)
	}
	if err := admin.ResetMFA(ctx, owner, "u-admin"); err != nil {
		t.Fatalf("owner resets admin: %v", err)
	}
	if err := admin.ResetMFA(ctx, owner, "u-imp"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("imported: %v", err)
	}
	if err := admin.ResetMFA(ctx, owner, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if err := admin.ResetMFA(ctx, owner, "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign: %v", err)
	}
	aw.Flush()
	var ok, refused int
	for _, r := range ms.AuditRows {
		if r.EventType != string(audit.MFAReset) {
			continue
		}
		switch r.Outcome {
		case "ok":
			ok++
			if r.SubjectID == nil || *r.SubjectID != "u-bob" && *r.SubjectID != "u-admin" {
				t.Fatalf("%+v", r)
			}
			if *r.SubjectID == "u-bob" && !strings.Contains(string(r.Details), `"methods":["totp","webauthn","recovery"]`) {
				t.Fatalf("details %s", r.Details)
			}
		case "refused":
			refused++
		}
	}
	if ok != 2 || refused != 2 {
		t.Fatalf("audit ok=%d refused=%d", ok, refused)
	}
}

type failReset struct {
	*memstore.Store
	fail string
}

func (f failReset) ResetMFA(ctx context.Context, tid, uid string) error {
	if f.fail == "reset" {
		return errors.New("down")
	}
	return f.Store.ResetMFA(ctx, tid, uid)
}
func (f failReset) Roles(ctx context.Context, tid, uid string) ([]string, error) {
	if f.fail == "roles" {
		return nil, errors.New("down")
	}
	return f.Store.Roles(ctx, tid, uid)
}
func (f failReset) ListWebAuthnCredentials(ctx context.Context, tid, uid string) ([]store.WebAuthnCredential, error) {
	if f.fail == "keys" {
		return nil, errors.New("down")
	}
	return f.Store.ListWebAuthnCredentials(ctx, tid, uid)
}
func (f failReset) ListRecoveryCodeHashes(ctx context.Context, tid, uid string) ([]string, error) {
	if f.fail == "codes" {
		return nil, errors.New("down")
	}
	return f.Store.ListRecoveryCodeHashes(ctx, tid, uid)
}

func TestAdminResetMFAFailures(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u-bob", TenantID: tA, Email: "bob@x.test", Status: "active"})
	c := cache.New(cache.NewMemory())
	actor := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", TenantID: tA, Roles: []string{"owner"}}
	for _, f := range []string{"roles", "keys", "codes", "reset"} {
		sm := session.New(ms, c, nil)
		if err := NewAdmin(failReset{ms, f}, sm, nil).ResetMFA(ctx, actor, "u-bob"); err == nil {
			t.Errorf("%s failure ignored", f)
		}
	}
	if rank([]string{"operator"}) <= rank([]string{"owner"}) || rank([]string{"member"}) != 0 {
		t.Fatal("rank")
	}
}
