package tenantctx

import (
	"context"
	"errors"
	"testing"

	"github.com/go-freya/freya/authn"
	"github.com/go-freya/freya/identity"
)

func TestActorRoundTrip(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("empty context has no actor")
	}
	a := Actor{Kind: KindUser, UserID: "u1", TenantID: "t1", SessionID: "s1", Roles: []string{"admin"}}
	got, ok := FromContext(WithActor(context.Background(), a))
	if !ok || got.UserID != "u1" || !got.HasRole("admin") || got.HasRole("owner") {
		t.Fatalf("%+v %v", got, ok)
	}
	if !a.IsAdmin() || a.IsOwner() {
		t.Fatal("role helpers")
	}
	o := Actor{Kind: KindUser, Roles: []string{"owner"}}
	if !o.IsOwner() || !o.IsAdmin() {
		t.Fatal("owner implies admin")
	}
}

func TestRequireTenant(t *testing.T) {
	var refused []Refusal
	guard := Guard{OnRefusal: func(r Refusal) { refused = append(refused, r) }}
	ctx := WithActor(context.Background(), Actor{Kind: KindUser, UserID: "u1", TenantID: "t1"})
	if err := guard.Require(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	err := guard.Require(ctx, "t2")
	if !errors.Is(err, ErrCrossTenant) || len(refused) != 1 || refused[0].ActorTenant != "t1" || refused[0].TargetTenant != "t2" {
		t.Fatalf("cross tenant: %v %+v", err, refused)
	}
	if err := guard.Require(context.Background(), "t1"); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
	if err := guard.Require(ctx, ""); !errors.Is(err, ErrCrossTenant) {
		t.Fatal("empty target must be refused")
	}
	// Operators need an active grant for a foreign tenant.
	op := WithActor(context.Background(), Actor{Kind: KindOperator, UserID: "op", TenantID: "platform"})
	if err := guard.Require(op, "t1"); !errors.Is(err, ErrNoOperatorGrant) {
		t.Fatalf("operator without grant: %v", err)
	}
	if err := guard.Require(WithOperatorGrant(op, "g1", "t1"), "t1"); err != nil {
		t.Fatalf("operator with grant: %v", err)
	}
	if err := guard.Require(WithOperatorGrant(op, "g1", "t1"), "t3"); !errors.Is(err, ErrNoOperatorGrant) {
		t.Fatal("grant is tenant-specific")
	}
	if err := guard.Require(op, "platform"); err != nil {
		t.Fatalf("operator in own tenant: %v", err)
	}
	// Services are scoped by the tenant they name; they hold no tenant of their own.
	svc := WithActor(context.Background(), Actor{Kind: KindService, ServiceID: "spiffe://example.org/svc/billing"})
	if err := guard.Require(svc, "t9"); err != nil {
		t.Fatalf("service: %v", err)
	}
	if _, ok := OperatorGrant(op); ok {
		t.Fatal("no grant expected")
	}
	if g, ok := OperatorGrant(WithOperatorGrant(op, "g1", "t1")); !ok || g.ID != "g1" || g.TenantID != "t1" {
		t.Fatalf("grant %+v", g)
	}
}

func TestFromPeer(t *testing.T) {
	p := authn.PeerIdentity{ID: identity.ForService("example.org", "billing"), ServiceName: "billing"}
	a := ActorFromService(p)
	if a.Kind != KindService || a.ServiceID != "spiffe://example.org/svc/billing" {
		t.Fatalf("%+v", a)
	}
	if !ValidTenantID("0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55") || ValidTenantID("x") || ValidTenantID("") {
		t.Fatal("tenant id validation")
	}
}
