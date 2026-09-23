package user

import (
	"context"
	"errors"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenant"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

func TestAdminOperations(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddTenant(store.Tenant{ID: tB, Slug: "globex", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddRole(store.Role{ID: "r-owner", TenantID: tA, Slug: "owner", Builtin: true})
	ms.AddRole(store.Role{ID: "r-member", TenantID: tA, Slug: "member", Builtin: true})
	ms.AddUser(store.User{ID: "u-owner", TenantID: tA, Email: "owner@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "u-bob", TenantID: tA, Email: "bob@x.test", DisplayName: "Bob", Status: "active"})
	ms.AddUser(store.User{ID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77", TenantID: tB, Email: "eve@x.test", Status: "active"})
	_ = ms.ReplaceBindings(ctx, tA, "u-owner", "", []string{"r-owner"})
	_ = ms.ReplaceBindings(ctx, tA, "u-bob", "", []string{"r-member"})
	c := cache.New(cache.NewMemory())
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	sm := session.New(ms, c, aw)
	admin := NewAdmin(ms, sm, aw)
	actor := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", TenantID: tA, Roles: []string{"owner"}}
	actorCtx := tenantctx.WithActor(ctx, actor)

	users, err := admin.List(ctx, actor, "bo", "")
	if err != nil || len(users) != 1 || users[0].Email != "bob@x.test" || users[0].Roles[0] != "member" {
		t.Fatalf("%v %v", users, err)
	}
	if users, _ := admin.List(ctx, actor, "", "deactivated"); len(users) != 0 {
		t.Fatal("status filter")
	}
	// Deactivation ends sessions and blocks sign-in.
	_, secret, _ := sm.Create(ctx, session.CreateParams{TenantID: tA, UserID: "u-bob", Policy: tenant.DefaultPolicy()})
	if err := admin.Deactivate(actorCtx, actor, "u-bob"); err != nil {
		t.Fatal(err)
	}
	if u, _ := ms.User(ctx, tA, "u-bob"); u.Status != "deactivated" {
		t.Fatal("status")
	}
	if _, err := sm.Resolve(ctx, secret); !errors.Is(err, session.ErrNoSession) {
		t.Fatal("session survived deactivation")
	}
	if err := admin.Reactivate(actorCtx, actor, "u-bob"); err != nil {
		t.Fatal(err)
	}
	if u, _ := ms.User(ctx, tA, "u-bob"); u.Status != "active" {
		t.Fatal("reactivate")
	}
	if _, err := sm.Resolve(ctx, secret); !errors.Is(err, session.ErrNoSession) {
		t.Fatal("sessions must not come back")
	}
	// Force sign-out.
	_, secret2, _ := sm.Create(ctx, session.CreateParams{TenantID: tA, UserID: "u-bob", Policy: tenant.DefaultPolicy()})
	if err := admin.ForceSignout(actorCtx, actor, "u-bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := sm.Resolve(ctx, secret2); !errors.Is(err, session.ErrNoSession) {
		t.Fatal("force sign-out")
	}
	// Last owner cannot be deactivated.
	if err := admin.Deactivate(actorCtx, actor, "u-owner"); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("last owner: %v", err)
	}
	// Foreign tenant id → not found + cross_tenant_refused audit.
	if err := admin.Deactivate(actorCtx, actor, "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign user: %v", err)
	}
	if err := admin.ForceSignout(actorCtx, actor, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown user")
	}
	aw.Close()
	types := map[string]int{}
	for _, r := range ms.AuditRows {
		types[r.EventType]++
	}
	if types["user_deactivated"] != 2 || types["user_reactivated"] != 1 || types["cross_tenant_refused"] != 1 || types["session_revoked"] < 2 {
		t.Fatalf("audit %v", types)
	}
}

// Research D10: an imported account is neither deactivated nor reactivated —
// deactivate → reactivate would otherwise turn a password-less, never-invited
// row into an active account. The refusal leaves status and sessions alone.
func TestAdminRefusesImported(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddRole(store.Role{ID: "r-owner", TenantID: tA, Slug: "owner", Builtin: true})
	ms.AddUser(store.User{ID: "u-owner", TenantID: tA, Email: "owner@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "u-imp", TenantID: tA, Email: "imp@x.test", DisplayName: "Imp", Status: "imported"})
	_ = ms.ReplaceBindings(ctx, tA, "u-owner", "", []string{"r-owner"})
	c := cache.New(cache.NewMemory())
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	sm := session.New(ms, c, aw)
	admin := NewAdmin(ms, sm, aw)
	actor := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", TenantID: tA, Roles: []string{"owner"}}
	actorCtx := tenantctx.WithActor(ctx, actor)

	// A (stray) session proves the refusal happens before any revocation.
	_, secret, err := sm.Create(ctx, session.CreateParams{TenantID: tA, UserID: "u-imp", Policy: tenant.DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	for name, op := range map[string]func(context.Context, tenantctx.Actor, string) error{
		"deactivate": admin.Deactivate,
		"reactivate": admin.Reactivate,
	} {
		if err := op(actorCtx, actor, "u-imp"); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("%s imported: want ErrInvalidState, got %v", name, err)
		}
		if u, _ := ms.User(ctx, tA, "u-imp"); u.Status != "imported" {
			t.Fatalf("%s imported changed status to %q", name, u.Status)
		}
		if _, err := sm.Resolve(ctx, secret); err != nil {
			t.Fatalf("%s imported touched sessions: %v", name, err)
		}
	}
	// Deactivate then reactivate in sequence must not reach active either.
	_ = admin.Deactivate(actorCtx, actor, "u-imp")
	_ = admin.Reactivate(actorCtx, actor, "u-imp")
	if u, _ := ms.User(ctx, tA, "u-imp"); u.Status != "imported" {
		t.Fatalf("deactivate→reactivate moved imported to %q", u.Status)
	}
	aw.Close()
	for _, r := range ms.AuditRows {
		if r.EventType == "session_revoked" || ((r.EventType == "user_deactivated" || r.EventType == "user_reactivated") && r.Outcome == "ok") {
			t.Fatalf("refused operation audited as done: %+v", r)
		}
	}
}
