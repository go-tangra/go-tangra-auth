package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-freya/freya/authn"
	"github.com/go-freya/freya/identity"
	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

func TestAuthorizationServer(t *testing.T) {
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tid, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u1", TenantID: tid, Email: "a@x", Status: "active"})
	c := authz.New(authz.NewFake(), cache.New(cache.NewMemory()), nil)
	srv := &AuthorizationServer{Decider: authz.NewDecider(ms, c, nil), Registry: authz.NewRegistry(ms, c, nil)}
	// Without a verified service peer the registrant is unknown.
	if _, err := srv.RegisterPermissions(context.Background(), &authv1.RegisterPermissionsRequest{TenantIds: []string{tid}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("%v", err)
	}
	// With a service actor (what the Freya authn stage provides) registration and checks work.
	ctx := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindService, ServiceID: "spiffe://example.org/svc/billing"})
	srv2 := &AuthorizationServer{Decider: srv.Decider, Registry: srv.Registry}
	// Bypass serviceCtx by calling the registry directly for setup, then exercise Check.
	if _, err := srv2.Registry.Register(ctx, tid, "svc", []authz.Permission{{Resource: "invoices", Action: "read"}}); err != nil {
		t.Fatal(err)
	}
	resp, err := srv2.Check(ctx, &authv1.CheckRequest{TenantId: tid, UserId: "u1", Resource: "invoices", Action: "read"})
	if err != nil || resp.Allowed || resp.Reason != authz.ReasonNoPermission {
		t.Fatalf("%v %v", resp, err)
	}
	if _, err := srv2.Check(ctx, &authv1.CheckRequest{TenantId: "bad", UserId: "u1", Resource: "invoices", Action: "read"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("%v", err)
	}
	batch, err := srv2.BatchCheck(ctx, &authv1.BatchCheckRequest{TenantId: tid, UserId: "u1", Permissions: []*authv1.PermissionRef{{Resource: "invoices", Action: "read"}, {Resource: "x", Action: "y"}}})
	if err != nil || len(batch.Results) != 2 || batch.Results[1].Reason != authz.ReasonUnknownPermission {
		t.Fatalf("%v %v", batch, err)
	}
	if _, err := srv2.BatchCheck(ctx, &authv1.BatchCheckRequest{TenantId: tid, UserId: "u1"}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("empty batch accepted")
	}
}

func TestRegisterPermissionsBuiltinGrants(t *testing.T) {
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tid, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u1", TenantID: tid, Email: "a@x", Status: "active"})
	ms.AddRole(store.Role{ID: "r-member", TenantID: tid, Slug: "member", DisplayName: "Member", Builtin: true})
	c := authz.New(authz.NewFake(), cache.New(cache.NewMemory()), nil)
	roles := authz.NewRoles(ms, c, authz.NewEscalation(c), nil)
	srv := &AuthorizationServer{Decider: authz.NewDecider(ms, c, nil), Registry: authz.NewRegistry(ms, c, nil), Roles: roles}
	id, _ := identity.NewSPIFFEID("example.org", "warden")
	ctx := authn.WithPeer(context.Background(), authn.PeerIdentity{ID: id, ServiceName: "warden"})
	perms := []*authv1.PermissionDef{{Resource: "secrets", Action: "read"}, {Resource: "secrets", Action: "write"}}
	// A grant naming a permission outside the request, or a non-builtin role, is refused.
	if _, err := srv.RegisterPermissions(ctx, &authv1.RegisterPermissionsRequest{Permissions: perms, TenantIds: []string{tid},
		BuiltinGrants: []*authv1.BuiltinGrant{{Role: "member", Permissions: []string{"users:manage"}}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("foreign permission: %v", err)
	}
	if _, err := srv.RegisterPermissions(ctx, &authv1.RegisterPermissionsRequest{Permissions: perms, TenantIds: []string{tid},
		BuiltinGrants: []*authv1.BuiltinGrant{{Role: "billing", Permissions: []string{"secrets:read"}}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("custom role: %v", err)
	}
	// Without a Roles service grants are refused outright.
	noRoles := &AuthorizationServer{Decider: srv.Decider, Registry: srv.Registry}
	if _, err := noRoles.RegisterPermissions(ctx, &authv1.RegisterPermissionsRequest{Permissions: perms, TenantIds: []string{tid},
		BuiltinGrants: []*authv1.BuiltinGrant{{Role: "member", Permissions: []string{"secrets:read"}}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no roles: %v", err)
	}
	// A valid grant lands on the builtin role (idempotently); an absent builtin role is skipped.
	req := &authv1.RegisterPermissionsRequest{Permissions: perms, TenantIds: []string{tid},
		BuiltinGrants: []*authv1.BuiltinGrant{{Role: "member", Permissions: []string{"secrets:read"}}, {Role: "auditor", Permissions: []string{"secrets:read"}}}}
	for i := 0; i < 2; i++ {
		if resp, err := srv.RegisterPermissions(ctx, req); err != nil || resp.Registered != 2 {
			t.Fatalf("%v %v", resp, err)
		}
	}
	got, err := ms.RolePermissions(context.Background(), tid, "r-member")
	if err != nil || len(got) != 1 || got[0] != [2]string{"secrets", "read"} {
		t.Fatalf("member permissions: %v %v", got, err)
	}
}
