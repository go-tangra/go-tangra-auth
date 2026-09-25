package tenant_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
	"github.com/go-tangra/go-tangra-auth/v4/internal/invite"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

const tP = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c11"

type sink struct{}

func (sink) Deliver(context.Context, email.Message) (email.Outcome, error) { return email.Sent, nil }

type fixture struct {
	svc    *tenant.Service
	grants *tenant.Grants
	az     *authz.Client
	ms     *memstore.Store
	fga    *authz.Fake
	sm     *session.Manager
	aw     *audit.Writer
	op     context.Context
	user   context.Context
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tP, Slug: "platform", Status: "active", Kind: "platform", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "op", TenantID: tP, Email: "ops@x", Status: "active"})
	c := cache.New(cache.NewMemory())
	fga := authz.NewFake()
	az := authz.New(fga, c, nil)
	aw := audit.NewWriter(ms, nil)
	sm := session.New(ms, c, aw)
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{1}, 32))
	inv := invite.New(ms, email.NewOutbox(env, sink{}, nil, 3, nil), az, aw, "https://auth.example.org")
	f := &fixture{svc: tenant.New(ms, inv, sm, az, c, aw), grants: tenant.NewGrants(ms, aw), az: az, ms: ms, fga: fga, sm: sm, aw: aw}
	f.op = tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindOperator, UserID: "op", TenantID: tP})
	f.user = tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tP, Roles: []string{"owner"}})
	return f
}

func (f *fixture) auditTypes() map[string]int {
	f.aw.Close()
	out := map[string]int{}
	for _, r := range f.ms.AuditRows {
		out[r.EventType]++
	}
	return out
}

func TestCreateSuspendReactivate(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.svc.Create(f.user, "acme", "Acme", "owner@acme.test"); !errors.Is(err, tenant.ErrNotOperator) {
		t.Fatalf("non-operator: %v", err)
	}
	for _, bad := range [][3]string{{"Acme", "Acme", "o@x"}, {"api", "Acme", "o@x"}, {"acme", "", "o@x"}, {"acme", "Acme", "not-an-email"}} {
		if _, err := f.svc.Create(f.op, bad[0], bad[1], bad[2]); !errors.Is(err, tenant.ErrValidation) {
			t.Errorf("%v accepted: %v", bad, err)
		}
	}
	created, err := f.svc.Create(f.op, "acme", "Acme", "owner@acme.test")
	if err != nil || created.Tenant.Slug != "acme" || created.InvitationID == "" {
		t.Fatalf("%+v %v", created, err)
	}
	tid := created.Tenant.ID
	roles, _ := f.ms.ListRoles(ctx, tid)
	if len(roles) != 3 {
		t.Fatalf("builtin roles %v", roles)
	}
	if ok, _ := f.fga.Check(ctx, authz.RoleTenantTuple(tid, "owner")); !ok {
		t.Fatal("role tuple missing")
	}
	inv := f.ms.Invitations[created.InvitationID]
	if inv.Email != "owner@acme.test" || len(inv.RoleIDs) != 1 {
		t.Fatalf("owner invitation %+v", inv)
	}
	if _, err := f.svc.Create(f.op, "acme", "Again", "o@x"); !errors.Is(err, tenant.ErrValidation) {
		t.Fatal("duplicate slug")
	}
	// Policy defaults; platform tenant forces MFA.
	pol, err := f.svc.GetPolicy(f.op, tP)
	if err != nil || !pol.MFARequired {
		t.Fatalf("%+v %v", pol, err)
	}
	p := tenant.DefaultPolicy()
	p.MFARequired = false
	if got, err := f.svc.UpdatePolicy(f.op, tP, p); err != nil || !got.MFARequired {
		t.Fatalf("platform must keep MFA: %+v %v", got, err)
	}
	p.SessionLifetime = tenant.Duration(48 * time.Hour)
	if _, err := f.svc.UpdatePolicy(f.op, tP, p); !errors.Is(err, tenant.ErrValidation) {
		t.Fatal("invalid policy accepted")
	}
	// A customer user cannot read the platform policy.
	acme := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u2", TenantID: tid, Roles: []string{"owner"}})
	if _, err := f.svc.GetPolicy(acme, tP); err == nil {
		t.Fatal("cross-tenant policy read")
	}
	// Suspension revokes every session and marks the tenant.
	f.ms.AddUser(store.User{ID: "u2", TenantID: tid, Email: "u2@acme.test", Status: "active"})
	_, secret, _ := f.sm.Create(ctx, session.CreateParams{TenantID: tid, UserID: "u2", Policy: tenant.DefaultPolicy()})
	if err := f.svc.Suspend(f.op, tid); err != nil {
		t.Fatal(err)
	}
	if tn, _ := f.ms.Tenant(ctx, tid); tn.Status != "suspended" {
		t.Fatal("status")
	}
	if _, err := f.sm.Resolve(ctx, secret); !errors.Is(err, session.ErrNoSession) {
		t.Fatal("session survived suspension")
	}
	if err := f.svc.Suspend(f.op, tP); !errors.Is(err, tenant.ErrValidation) {
		t.Fatal("platform suspended")
	}
	if err := f.svc.Reactivate(f.op, tid); err != nil {
		t.Fatal(err)
	}
	if tn, _ := f.ms.Tenant(ctx, tid); tn.Status != "active" {
		t.Fatal("reactivate")
	}
	list, err := f.svc.List(f.op)
	if err != nil || len(list) != 2 {
		t.Fatal(list, err)
	}
	if _, err := f.svc.List(f.user); !errors.Is(err, tenant.ErrNotOperator) {
		t.Fatal("list by non-operator")
	}
	types := f.auditTypes()
	if types["tenant_created"] != 1 || types["tenant_suspended"] != 1 || types["tenant_reactivated"] != 1 || types["policy_updated"] != 1 || types["invite_created"] != 1 {
		t.Fatalf("audit %v", types)
	}
}

func TestOperatorGrants(t *testing.T) {
	f := setup(t)
	created, _ := f.svc.Create(f.op, "acme", "Acme", "owner@acme.test")
	tid := created.Tenant.ID
	// In-tenant action without a grant is refused and audited.
	if _, err := f.grants.Apply(f.op, tid); !errors.Is(err, tenant.ErrNoGrant) {
		t.Fatalf("no grant: %v", err)
	}
	for _, bad := range []struct {
		reason string
		d      time.Duration
		tid    string
	}{{"short", time.Hour, tid}, {"support ticket 1234", 5 * time.Hour, tid}, {"support ticket 1234", 0, tid}, {"support ticket 1234", time.Hour, tP}, {"support ticket 1234", time.Hour, "nope"}} {
		if _, err := f.grants.Create(f.op, bad.tid, bad.reason, bad.d); !errors.Is(err, tenant.ErrValidation) && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%+v accepted: %v", bad, err)
		}
	}
	if _, err := f.grants.Create(f.user, tid, "support ticket 1234", time.Hour); !errors.Is(err, tenant.ErrNotOperator) {
		t.Fatal("non-operator grant")
	}
	g, err := f.grants.Create(f.op, tid, "support ticket 1234", time.Hour)
	if err != nil || g.TenantID != tid {
		t.Fatal(g, err)
	}
	gctx, err := f.grants.Apply(f.op, tid)
	if err != nil {
		t.Fatal(err)
	}
	if gr, ok := tenantctx.OperatorGrant(gctx); !ok || gr.ID != g.ID {
		t.Fatal("grant not attached")
	}
	if err := f.az.Guard().Require(gctx, tid); err != nil {
		t.Fatalf("guard must accept the grant: %v", err)
	}
	// Own tenant needs no grant; expiry ends access.
	if _, err := f.grants.Apply(f.op, tP); err != nil {
		t.Fatal(err)
	}
	f.ms.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := f.grants.Apply(f.op, tid); !errors.Is(err, tenant.ErrNoGrant) {
		t.Fatal("expired grant applied")
	}
	types := f.auditTypes()
	if types["operator_grant_created"] != 1 || types["operator_grant_used"] != 1 || types["cross_tenant_refused"] != 2 {
		t.Fatalf("audit %v", types)
	}
}
