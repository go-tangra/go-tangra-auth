package user

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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

// Research D13 / FR-009: RemoveImported hard-deletes a never-invited
// imported user (the directory link cascades) without any e-mail, and refuses
// every other status so it can never be used as a general user delete.
func TestAdminRemoveImported(t *testing.T) {
	const foreignImp = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c78"
	ctx := context.Background()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tA, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddTenant(store.Tenant{ID: tB, Slug: "globex", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddRole(store.Role{ID: "r-owner", TenantID: tA, Slug: "owner", Builtin: true})
	ms.AddUser(store.User{ID: "u-owner", TenantID: tA, Email: "owner@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "u-imp", TenantID: tA, Email: "imp@x.test", DisplayName: "Imp", Status: "imported"})
	ms.AddUser(store.User{ID: "u-active", TenantID: tA, Email: "active@x.test", Status: "active"})
	ms.AddUser(store.User{ID: "u-invited", TenantID: tA, Email: "invited@x.test", Status: "invited"})
	ms.AddUser(store.User{ID: "u-deact", TenantID: tA, Email: "deact@x.test", Status: "deactivated"})
	ms.AddUser(store.User{ID: foreignImp, TenantID: tB, Email: "far@x.test", Status: "imported"})
	_ = ms.ReplaceBindings(ctx, tA, "u-owner", "", []string{"r-owner"})
	connA, connB := "c-a", "c-b"
	now := time.Now()
	for _, c := range []store.DirectoryConnection{{ID: connA, TenantID: tA, Name: "corp"}, {ID: connB, TenantID: tB, Name: "corp"}} {
		if err := ms.InsertDirectoryConnection(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	links := []store.DirectoryLink{
		{UserID: "u-imp", TenantID: tA, ConnectionID: &connA, ConnectionName: "corp", DirectoryUID: "imp", FirstImportedAt: now, LastImportedAt: now},
		// An activated (now active) import keeps its link; refusal must keep it too.
		{UserID: "u-active", TenantID: tA, ConnectionID: &connA, ConnectionName: "corp", DirectoryUID: "act", FirstImportedAt: now, LastImportedAt: now},
		{UserID: foreignImp, TenantID: tB, ConnectionID: &connB, ConnectionName: "corp", DirectoryUID: "far", FirstImportedAt: now, LastImportedAt: now},
	}
	for _, l := range links {
		if err := ms.UpsertLink(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	c := cache.New(cache.NewMemory())
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	sm := session.New(ms, c, aw)
	admin := NewAdmin(ms, sm, aw)
	actor := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", TenantID: tA, Roles: []string{"owner"}}
	actorCtx := tenantctx.WithActor(ctx, actor)

	// Any status other than imported is refused and left untouched.
	for uid, status := range map[string]string{"u-active": "active", "u-invited": "invited", "u-deact": "deactivated", "u-owner": "active"} {
		if err := admin.RemoveImported(actorCtx, actor, uid); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("remove %s (%s): want ErrInvalidState, got %v", uid, status, err)
		}
		if u, err := ms.User(ctx, tA, uid); err != nil || u.Status != status {
			t.Fatalf("remove %s refused but user changed: %+v %v", uid, u, err)
		}
	}
	if l, _ := ms.LinksByUIDs(ctx, tA, connA, []string{"act"}); len(l) != 1 {
		t.Fatalf("refused remove dropped the active user's link: %v", l)
	}

	// The imported user is deleted, its link cascades, and no e-mail is queued.
	if err := admin.RemoveImported(actorCtx, actor, "u-imp"); err != nil {
		t.Fatal(err)
	}
	if _, err := ms.User(ctx, tA, "u-imp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("imported user survived: %v", err)
	}
	if l, _ := ms.LinksByUIDs(ctx, tA, connA, []string{"imp"}); len(l) != 0 {
		t.Fatalf("link did not cascade: %v", l)
	}
	if users, _ := admin.List(ctx, actor, "", "imported"); len(users) != 0 {
		t.Fatalf("removed user still listed: %v", users)
	}
	if len(ms.Outbox) != 0 {
		t.Fatalf("remove queued e-mail: %+v", ms.Outbox)
	}
	// A second remove finds nothing.
	if err := admin.RemoveImported(actorCtx, actor, "u-imp"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove: %v", err)
	}
	// Another tenant's imported user → not found (audited), never deleted.
	if err := admin.RemoveImported(actorCtx, actor, foreignImp); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign user: %v", err)
	}
	if u, err := ms.User(ctx, tB, foreignImp); err != nil || u.Status != "imported" {
		t.Fatalf("foreign imported user touched: %+v %v", u, err)
	}
	if l, _ := ms.LinksByUIDs(ctx, tB, connB, []string{"far"}); len(l) != 1 {
		t.Fatal("foreign link touched")
	}
	if err := admin.RemoveImported(actorCtx, actor, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	if len(ms.Outbox) != 0 {
		t.Fatalf("remove queued e-mail: %+v", ms.Outbox)
	}

	aw.Close()
	deleted, crossTenant := 0, 0
	for _, r := range ms.AuditRows {
		switch r.EventType {
		case "imported_user_deleted":
			if r.Outcome != "ok" {
				continue
			}
			deleted++
			if r.TenantID != tA || r.ActorUserID == nil || *r.ActorUserID != "u-owner" || r.SubjectKind != "user" || r.SubjectID == nil || *r.SubjectID != "u-imp" {
				t.Fatalf("imported_user_deleted row: %+v", r)
			}
			// SR-007: no e-mail of a directory person in the audit.
			if strings.Contains(string(r.Details), "imp@x.test") {
				t.Fatalf("audit leaks the e-mail: %s", r.Details)
			}
		case "cross_tenant_refused":
			crossTenant++
		}
	}
	if deleted != 1 || crossTenant != 1 {
		t.Fatalf("audit: %d imported_user_deleted ok, %d cross_tenant_refused", deleted, crossTenant)
	}
}
