//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/grpcapi"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra/v4/authn"
	"github.com/go-tangra/go-tangra/v4/identity"
)

// Feature 019 against PostgreSQL, Valkey and OpenFGA v1.20.0.

func peerCtx(t *testing.T, svc string) context.Context {
	t.Helper()
	id, err := identity.NewSPIFFEID("example.org", svc)
	if err != nil {
		t.Fatal(err)
	}
	return authn.WithPeer(context.Background(), authn.PeerIdentity{ID: id, ServiceName: svc})
}

// authzServer is the auth.v1.Authorization server as Build wires it.
func authzServer(e *Env) *grpcapi.AuthorizationServer {
	return &grpcapi.AuthorizationServer{Decider: e.App.Decider, Registry: e.App.Registry, Roles: e.App.Roles, Modules: e.App.Modules, Gateway: "gateway", Audit: e.App.Audit}
}

func sysCtx() context.Context {
	return tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindSystem})
}

// legacyGrant gives a role a pre-019 grant (mirror row + tuple).
func legacyGrant(t *testing.T, e *Env, tid, roleID, slug string, refs ...authz.PermissionRef) {
	t.Helper()
	var tuples []authz.Tuple
	for _, r := range refs {
		tuples = append(tuples, authz.GrantTuple(tid, slug, r))
	}
	tuples = append(tuples, authz.RoleTenantTuple(tid, slug))
	if err := e.App.Authz.Write(sysCtx(), tid, tuples, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.App.Store.Tx(context.Background(), store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		cur, err := store.ListRolePermissions(context.Background(), tx, tid, roleID)
		if err != nil {
			return err
		}
		return store.ReplaceRolePermissions(context.Background(), tx, tid, roleID, append(cur, refs...))
	}); err != nil {
		t.Fatal(err)
	}
}

func checkAs(t *testing.T, srv *grpcapi.AuthorizationServer, ctx context.Context, tid, uid, module, res, act string) bool {
	t.Helper()
	resp, err := srv.Check(ctx, &authv1.CheckRequest{TenantId: tid, UserId: uid, Resource: res, Action: act, Module: module})
	if err != nil {
		t.Fatalf("check %s:%s:%s: %v", module, res, act, err)
	}
	return resp.GetAllowed()
}

// TestModuleScopeRollout (T019): pre-019 legacy data, an old gateway and old
// modules (no module field) → access unchanged; a module-scoped role is
// refused in other modules (real OpenFGA); verify is clean; prune-legacy
// keeps access; a tenant created mid-rollout keeps legacy checks working.
func TestModuleScopeRollout(t *testing.T) {
	e := Start(t)
	srv := authzServer(e)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	_, carol := e.Seed("acme", "carol@acme.test", pw, "")
	_, dave := e.Seed("acme", "dave@acme.test", pw, "")
	gw := peerCtx(t, "gateway")
	legacyPerms := []*authv1.PermissionDef{{Resource: "backup", Action: "manage"}, {Resource: "stats", Action: "read"}}
	// Old gateway: legacy rows only.
	if _, err := srv.RegisterPermissions(gw, &authv1.RegisterPermissionsRequest{Permissions: legacyPerms, TenantIds: []string{tid}}); err != nil {
		t.Fatal(err)
	}
	// A pre-019 custom role holding legacy backup:manage, held by carol.
	backupsID := store.NewID()
	if err := e.App.Store.Tx(context.Background(), store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		return store.InsertRole(context.Background(), tx, store.Role{ID: backupsID, TenantID: tid, Slug: "backups", DisplayName: "Backups"})
	}); err != nil {
		t.Fatal(err)
	}
	legacyGrant(t, e, tid, backupsID, "backups", authz.PermissionRef{Resource: "backup", Action: "manage"})
	e.Bind(tid, carol, map[string]string{"backups": backupsID}, "backups")
	if !checkAs(t, srv, gw, tid, carol, "", "backup", "manage") {
		t.Fatal("legacy fixture")
	}
	before, err := e.App.Verifier.Snapshot(sysCtx(), []string{tid})
	if err != nil {
		t.Fatal(err)
	}
	// Old modules register without a module: attributed to the caller.
	for _, m := range []string{"warden", "ipam"} {
		if _, err := srv.RegisterPermissions(peerCtx(t, m), &authv1.RegisterPermissionsRequest{Permissions: []*authv1.PermissionDef{{Resource: "backup", Action: "manage"}}, TenantIds: []string{tid}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []string{"warden", "ipam", ""} {
		if !checkAs(t, srv, gw, tid, carol, m, "backup", "manage") {
			t.Fatalf("carol lost %q backup:manage", m)
		}
	}
	// A new role with only warden's permission: refused for ipam (SC-002).
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	code, role := e.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": "warden-backups", "display_name": "Warden backups", "permissions": []string{"warden:backup:manage"}})
	if code != 201 {
		t.Fatalf("%d %v", code, role)
	}
	if code, out := e.JSON(http.MethodPut, "/api/v1/admin/users/"+dave+"/roles", map[string]any{"role_ids": []string{role["id"].(string)}}); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if !checkAs(t, srv, gw, tid, dave, "warden", "backup", "manage") || checkAs(t, srv, gw, tid, dave, "ipam", "backup", "manage") || checkAs(t, srv, gw, tid, dave, "", "backup", "manage") {
		t.Fatal("cross-module bleed against OpenFGA")
	}
	// A service may not ask about another module.
	if _, err := srv.Check(peerCtx(t, "warden"), &authv1.CheckRequest{TenantId: tid, UserId: dave, Resource: "backup", Action: "manage", Module: "ipam"}); err == nil {
		t.Fatal("foreign module check accepted")
	}
	// Mid-rollout tenant: the old gateway registers legacy rows, the old
	// module's built-in grant is mirrored to them.
	tid2, admin2 := e.Seed("globex", "admin@globex.test", pw, "")
	roles2 := e.SeedRoles(tid2)
	e.Bind(tid2, admin2, roles2, "admin")
	if _, err := e.App.Roles.EnsureBuiltin(sysCtx(), tid2, []string{"owner", "admin", "member", "auditor"}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.RegisterPermissions(gw, &authv1.RegisterPermissionsRequest{Permissions: legacyPerms, TenantIds: []string{tid2}}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.RegisterPermissions(peerCtx(t, "warden"), &authv1.RegisterPermissionsRequest{Permissions: legacyPerms, TenantIds: []string{tid2},
		BuiltinGrants: []*authv1.BuiltinGrant{{Role: "admin", Permissions: []string{"backup:manage"}}}}); err != nil {
		t.Fatal(err)
	}
	if !checkAs(t, srv, gw, tid2, admin2, "", "backup", "manage") || !checkAs(t, srv, gw, tid2, admin2, "warden", "backup", "manage") {
		t.Fatal("mid-rollout tenant: legacy check broken")
	}
	// verify, compare, prune.
	rep, err := e.App.Verifier.Verify(sysCtx(), []string{tid, tid2})
	if err != nil || !rep.Clean() {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	if rep, err := e.App.Verifier.Compare(sysCtx(), before); err != nil || rep.Losses() != 0 {
		t.Fatalf("compare: %+v %v", rep, err)
	}
	res, err := e.App.Verifier.PruneLegacy(sysCtx(), []string{tid, tid2}, false)
	if err != nil || res.Permissions != 4 {
		t.Fatalf("prune: %+v %v", res, err)
	}
	for _, m := range []string{"warden", "ipam"} {
		if !checkAs(t, srv, gw, tid, carol, m, "backup", "manage") {
			t.Fatalf("prune removed carol's %s access", m)
		}
	}
	if checkAs(t, srv, gw, tid, carol, "", "backup", "manage") {
		t.Fatal("legacy object still granted after prune")
	}
	if rep, err := e.App.Verifier.Compare(sysCtx(), before); err != nil || rep.Losses() != 0 {
		t.Fatalf("compare after prune: %+v %v", rep, err)
	}
	if n := e.AuditCount(tid, "permission_pruned"); n != 1 {
		t.Fatalf("permission_pruned %d", n)
	}
}

// TestModuleRolesEndToEnd (T044, T071): a module declares roles through the
// gRPC API; assigning the viewer grants exactly its permission; a tenant
// created afterwards has the module roles and auditor at once; retirement
// keeps the existing assignee's access and refuses new assignments; start-up
// reconciliation adopts a pre-019 custom auditor role.
func TestModuleRolesEndToEnd(t *testing.T) {
	e := Start(t)
	srv := authzServer(e)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid) // pre-019 shape: a custom "auditor"
	e.Bind(tid, owner, roles, "owner")
	_, carol := e.Seed("acme", "carol@acme.test", pw, "")
	_, dave := e.Seed("acme", "dave@acme.test", pw, "")
	if err := e.App.EnsureBuiltinRoles(context.Background()); err != nil {
		t.Fatal(err)
	}
	var aud store.Role
	_ = e.App.Store.Tx(context.Background(), store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		var err error
		aud, err = store.GetRole(context.Background(), tx, tid, roles["auditor"])
		return err
	})
	if !aud.Builtin || aud.Origin != store.OriginBuiltin {
		t.Fatalf("custom auditor not adopted: %+v", aud)
	}
	warden := &authv1.RegisterPermissionsRequest{Module: "warden", ModuleDisplayName: "Warden", DeclaresRoles: true, TenantIds: []string{tid},
		Permissions: []*authv1.PermissionDef{{Resource: "secrets", Action: "read"}, {Resource: "secrets", Action: "write"}, {Resource: "stats", Action: "read"}},
		Roles: []*authv1.ModuleRoleDef{
			{Slug: "administrator", DisplayName: "Warden administrator", Permissions: []string{"secrets:read", "secrets:write", "stats:read"}},
			{Slug: "viewer", DisplayName: "Warden viewer", Permissions: []string{"secrets:read"}},
		},
		BuiltinGrants: []*authv1.BuiltinGrant{{Role: "auditor", Permissions: []string{"stats:read"}}, {Role: "operator", Permissions: []string{"stats:read"}}}}
	resp, err := srv.RegisterPermissions(peerCtx(t, "warden"), warden)
	if err != nil || resp.GetRolesUpserted() != 2 {
		t.Fatalf("%v %v", resp, err)
	}
	if len(resp.GetSkippedGrants()) != 1 || resp.GetSkippedGrants()[0].GetRole() != "operator" {
		t.Fatalf("skipped grants %v", resp.GetSkippedGrants())
	}
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	_, list := e.JSON(http.MethodGet, "/api/v1/admin/roles", nil)
	_ = list
	viewerID := ""
	if err := e.App.Store.Tx(context.Background(), store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		rs, err := store.ListRoles(context.Background(), tx, tid)
		for _, r := range rs {
			if r.Slug == "m.warden.viewer" {
				viewerID = r.ID
			}
		}
		return err
	}); err != nil || viewerID == "" {
		t.Fatalf("viewer missing: %v", err)
	}
	if code, out := e.JSON(http.MethodPut, "/api/v1/admin/users/"+carol+"/roles", map[string]any{"role_ids": []string{viewerID}}); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	gw := peerCtx(t, "gateway")
	if !checkAs(t, srv, gw, tid, carol, "warden", "secrets", "read") || checkAs(t, srv, gw, tid, carol, "warden", "secrets", "write") {
		t.Fatal("viewer grants")
	}
	// Locked in the API.
	if code, out := e.JSON(http.MethodPut, "/api/v1/admin/roles/"+viewerID, map[string]any{"display_name": "x", "permissions": []string{"warden:secrets:write"}}); code != 403 || out["reason"] != "managed_role" {
		t.Fatalf("%d %v", code, out)
	}
	// Retire the viewer: carol keeps access, dave cannot get it.
	warden.Roles = warden.Roles[:1]
	if resp, err := srv.RegisterPermissions(peerCtx(t, "warden"), warden); err != nil || len(resp.GetRolesRetired()) != 1 {
		t.Fatalf("%v %v", resp, err)
	}
	if !checkAs(t, srv, gw, tid, carol, "warden", "secrets", "read") {
		t.Fatal("retirement removed access")
	}
	if code, out := e.JSON(http.MethodPut, "/api/v1/admin/users/"+dave+"/roles", map[string]any{"role_ids": []string{viewerID}}); code != 409 || out["reason"] != "role_retired" {
		t.Fatalf("%d %v", code, out)
	}
	warden.Roles = append(warden.Roles, &authv1.ModuleRoleDef{Slug: "viewer", DisplayName: "Warden viewer", Permissions: []string{"secrets:read"}})
	if _, err := srv.RegisterPermissions(peerCtx(t, "warden"), warden); err != nil {
		t.Fatal(err)
	}
	// A tenant created by an operator has the module roles and auditor at once.
	if _, err := e.App.Bootstrap(t.Context(), "ops@example.org"); err != nil {
		t.Fatal(err)
	}
	mail := e.LastMail("ops@example.org")
	tok := strings.TrimSpace(strings.Split(mail[strings.Index(mail, "token=")+6:], "\n")[0])
	op := e.Browser()
	if code, out := op.JSON(http.MethodPost, "/api/v1/invitations/accept", map[string]string{"token": tok, "display_name": "Ops", "password": "operator-password-1"}); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	code, out := op.JSON(http.MethodPost, "/api/v1/operator/tenants", map[string]string{"slug": "initech", "display_name": "Initech", "owner_email": "owner@initech.test"})
	if code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	tid3 := out["tenant"].(map[string]any)["id"].(string)
	have := map[string]bool{}
	_ = e.App.Store.Tx(context.Background(), store.Scope{TenantID: tid3}, func(tx pgx.Tx) error {
		rs, err := store.ListRoles(context.Background(), tx, tid3)
		for _, r := range rs {
			have[r.Slug] = true
		}
		return err
	})
	for _, s := range []string{"owner", "admin", "member", "auditor", "m.warden.administrator", "m.warden.viewer"} {
		if !have[s] {
			t.Fatalf("new tenant lacks %s: %v", s, have)
		}
	}
	if n := e.AuditCount(e.App.Modules.PlatformTenant, "module_registered"); n == 0 {
		t.Fatal("module_registered not audited")
	}
}
