package grpcapi

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra/v4/authn"
	"github.com/go-tangra/go-tangra/v4/identity"
)

type modSrv struct {
	c   *authz.Client
	ms  *memstore.Store
	srv *AuthorizationServer
	aw  *audit.Writer
	log *bytes.Buffer
}

func newModSrv(t *testing.T) *modSrv {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tid, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u1", TenantID: tid, Email: "a@x", Status: "active"})
	ms.AddRole(store.Role{ID: "r-member", TenantID: tid, Slug: "member", DisplayName: "Member", Builtin: true})
	ms.AddRole(store.Role{ID: "r-op", TenantID: tid, Slug: "operator", DisplayName: "Custom operator"})
	c := authz.New(authz.NewFake(), cache.New(cache.NewMemory()), nil)
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	reg := authz.NewRegistry(ms, c, aw)
	roles := authz.NewRoles(ms, c, authz.NewEscalation(c), aw)
	mods := authz.NewModules(ms, reg, roles, c, aw)
	mods.PlatformTenant = tid
	buf := &bytes.Buffer{}
	srv := &AuthorizationServer{Decider: authz.NewDecider(ms, c, aw), Registry: reg, Roles: roles, Modules: mods, Gateway: "gateway", Audit: aw,
		Log: slog.New(slog.NewTextHandler(buf, nil)), Tenants: func(context.Context) ([]string, error) { return []string{tid}, nil }}
	return &modSrv{c: c, ms: ms, srv: srv, aw: aw, log: buf}
}

func peer(t *testing.T, svc string) context.Context {
	t.Helper()
	id, err := identity.NewSPIFFEID("example.org", svc)
	if err != nil {
		t.Fatal(err)
	}
	return authn.WithPeer(context.Background(), authn.PeerIdentity{ID: id, ServiceName: svc})
}

func (m *modSrv) perms(t *testing.T) []string {
	t.Helper()
	ps, _ := m.ms.ListPermissions(context.Background(), tid)
	var out []string
	for _, p := range ps {
		out = append(out, p.Ref().String())
	}
	return out
}

var wardenPerms = []*authv1.PermissionDef{{Resource: "secrets", Action: "read"}, {Resource: "backup", Action: "manage"}}

// T014: the module comes from the verified identity; a module may register
// only itself; the gateway may register other modules but never roles or
// grants, and without a module only touches legacy rows.
func TestRegisterModuleAttribution(t *testing.T) {
	m := newModSrv(t)
	warden := peer(t, "warden")
	// Old module (no module field) → attributed to the caller.
	if _, err := m.srv.RegisterPermissions(warden, &authv1.RegisterPermissionsRequest{Permissions: wardenPerms}); err != nil {
		t.Fatal(err)
	}
	// Explicit own module → same.
	if _, err := m.srv.RegisterPermissions(warden, &authv1.RegisterPermissionsRequest{Module: "warden", ModuleDisplayName: "Warden", Permissions: wardenPerms}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.perms(t), ","); got != "warden:backup:manage,warden:secrets:read" {
		t.Fatal(got)
	}
	// Negative: warden registering for ipam is refused and audited.
	_, err := m.srv.RegisterPermissions(warden, &authv1.RegisterPermissionsRequest{Module: "ipam", Permissions: wardenPerms, TenantIds: []string{tid}})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "module_mismatch") {
		t.Fatalf("foreign module: %v", err)
	}
	m.aw.Flush()
	refused := 0
	for _, r := range m.ms.AuditRows {
		if r.EventType == string(audit.ModuleRegistered) && r.Outcome == "refused" && r.Reason == "module_mismatch" {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("module_mismatch audited %d times", refused)
	}
	gw := peer(t, "gateway")
	// Gateway on behalf of ipam → accepted under ipam.
	if _, err := m.srv.RegisterPermissions(gw, &authv1.RegisterPermissionsRequest{Module: "ipam", ModuleDisplayName: "IPAM", Permissions: []*authv1.PermissionDef{{Resource: "ipam", Action: "read"}}}); err != nil {
		t.Fatal(err)
	}
	// Gateway without a module → legacy rows only, never a "gateway" module.
	if _, err := m.srv.RegisterPermissions(gw, &authv1.RegisterPermissionsRequest{Permissions: []*authv1.PermissionDef{{Resource: "stats", Action: "read"}}}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.perms(t), ","); got != "stats:read,ipam:ipam:read,warden:backup:manage,warden:secrets:read" {
		t.Fatal(got)
	}
	mods, _ := m.ms.Modules(context.Background())
	for _, mod := range mods {
		if mod.Name == "gateway" {
			t.Fatal("a module named gateway was created")
		}
	}
	// Gateway with roles, declares_roles or grants → InvalidArgument.
	for name, req := range map[string]*authv1.RegisterPermissionsRequest{
		"roles":    {Module: "ipam", Permissions: wardenPerms, Roles: []*authv1.ModuleRoleDef{{Slug: "viewer", DisplayName: "V", Permissions: []string{"secrets:read"}}}},
		"declares": {Module: "ipam", Permissions: wardenPerms, DeclaresRoles: true},
		"grants":   {Module: "ipam", Permissions: wardenPerms, BuiltinGrants: []*authv1.BuiltinGrant{{Role: "member", Permissions: []string{"secrets:read"}}}},
	} {
		if _, err := m.srv.RegisterPermissions(gw, req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("gateway %s: %v", name, err)
		}
	}
	// Gateway for module auth → accepted, nothing changes.
	before := strings.Join(m.perms(t), ",")
	if _, err := m.srv.RegisterPermissions(gw, &authv1.RegisterPermissionsRequest{Module: "auth", Permissions: []*authv1.PermissionDef{{Resource: "evil", Action: "grant"}}}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(m.perms(t), ",") != before {
		t.Fatal("gateway changed auth's permissions")
	}
	// No identity is refused; limits and grammar are enforced.
	if _, err := m.srv.RegisterPermissions(context.Background(), &authv1.RegisterPermissionsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no identity: %v", err)
	}
	big := make([]*authv1.PermissionDef, 201)
	for i := range big {
		big[i] = &authv1.PermissionDef{Resource: "r", Action: "a"}
	}
	if _, err := m.srv.RegisterPermissions(warden, &authv1.RegisterPermissionsRequest{Permissions: big}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("201 permissions: %v", err)
	}
	roles := make([]*authv1.ModuleRoleDef, 21)
	if _, err := m.srv.RegisterPermissions(warden, &authv1.RegisterPermissionsRequest{Permissions: wardenPerms, Roles: roles}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("21 roles: %v", err)
	}
	if _, err := m.srv.RegisterPermissions(warden, &authv1.RegisterPermissionsRequest{Module: "Bad", Permissions: wardenPerms}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad module: %v", err)
	}
	if _, err := m.srv.RegisterPermissions(warden, &authv1.RegisterPermissionsRequest{Permissions: []*authv1.PermissionDef{{Resource: "Bad", Action: "x"}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad permission: %v", err)
	}
	if _, err := m.srv.RegisterPermissions(warden, &authv1.RegisterPermissionsRequest{Permissions: wardenPerms, TenantIds: []string{"nope"}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad tenant: %v", err)
	}
}

// T038/T070 through gRPC: roles and skipped grants come back in the
// response; rejected roles and skipped grants are logged, never silent.
func TestRegisterRolesAndSkippedGrants(t *testing.T) {
	m := newModSrv(t)
	resp, err := m.srv.RegisterPermissions(peer(t, "warden"), &authv1.RegisterPermissionsRequest{Module: "warden", ModuleDisplayName: "Warden", Permissions: wardenPerms, DeclaresRoles: true,
		Roles: []*authv1.ModuleRoleDef{
			{Slug: "viewer", DisplayName: "Warden viewer", Permissions: []string{"secrets:read"}},
			{Slug: "thief", DisplayName: "Thief", Permissions: []string{"users:manage"}},
		},
		BuiltinGrants: []*authv1.BuiltinGrant{{Role: "member", Permissions: []string{"secrets:read"}}, {Role: "operator", Permissions: []string{"backup:manage"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.RolesUpserted != 1 || len(resp.RoleErrors) != 1 || resp.RoleErrors[0].Slug != "thief" || resp.RoleErrors[0].Reason != authz.RoleForeignPermission {
		t.Fatalf("%+v", resp)
	}
	if len(resp.SkippedGrants) != 1 || resp.SkippedGrants[0].Role != "operator" || resp.SkippedGrants[0].Tenants != 1 || resp.SkippedGrants[0].Reason != "role_missing" ||
		len(resp.SkippedGrants[0].SampleTenantIds) != 1 {
		t.Fatalf("%+v", resp.SkippedGrants)
	}
	logs := m.log.String()
	if !strings.Contains(logs, "built-in grant skipped") || !strings.Contains(logs, "module role rejected") {
		t.Fatalf("not logged: %s", logs)
	}
	// The custom "operator" role got nothing (D6 gap closed).
	if got, _ := m.ms.RolePermissions(context.Background(), tid, "r-op"); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	// Retiring through a later registration.
	resp, err = m.srv.RegisterPermissions(peer(t, "warden"), &authv1.RegisterPermissionsRequest{Permissions: wardenPerms, DeclaresRoles: true})
	if err != nil || len(resp.RolesRetired) != 1 || resp.RolesRetired[0] != "viewer" {
		t.Fatalf("%+v %v", resp, err)
	}
	// Grant validation is unchanged: unknown role, foreign permission.
	if _, err := m.srv.RegisterPermissions(peer(t, "warden"), &authv1.RegisterPermissionsRequest{Permissions: wardenPerms, BuiltinGrants: []*authv1.BuiltinGrant{{Role: "custom", Permissions: []string{"secrets:read"}}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("custom grant role: %v", err)
	}
}

// T015: checks resolve the module from the caller; the gateway names it or
// asks the legacy object; any other service may not ask about another module.
func TestCheckModuleRules(t *testing.T) {
	m := newModSrv(t)
	ctx := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindSystem})
	// Legacy stats:read held by u1 through member; warden registers scoped.
	if _, err := m.srv.Registry.Register(ctx, tid, "", "gw", []authz.Permission{{Resource: "stats", Action: "read"}, {Resource: "backup", Action: "manage"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.srv.Roles.GrantBuiltin(ctx, tid, "member", []authz.PermissionRef{{Resource: "stats", Action: "read"}}); err != nil {
		t.Fatal(err)
	}
	_ = m.ms.ReplaceBindings(context.Background(), tid, "u1", "", []string{"r-member"})
	fgaWrite(t, m, authz.RoleAssignmentTuple(tid, "member", "u1"))
	if _, err := m.srv.RegisterPermissions(peer(t, "warden"), &authv1.RegisterPermissionsRequest{Permissions: []*authv1.PermissionDef{{Resource: "stats", Action: "read"}, {Resource: "backup", Action: "manage"}}}); err != nil {
		t.Fatal(err)
	}
	check := func(ctx context.Context, module string) (*authv1.CheckResponse, error) {
		return m.srv.Check(ctx, &authv1.CheckRequest{TenantId: tid, UserId: "u1", Resource: "stats", Action: "read", Module: module})
	}
	gw := peer(t, "gateway")
	for _, c := range []struct {
		name   string
		ctx    context.Context
		module string
		allow  bool
		code   codes.Code
	}{
		{"gateway scoped", gw, "warden", true, codes.OK},
		{"gateway legacy", gw, "", true, codes.OK},
		{"gateway unknown module falls back to legacy", gw, "lcm", true, codes.OK},
		{"service own implicit", peer(t, "warden"), "", true, codes.OK},
		{"service own explicit", peer(t, "warden"), "warden", true, codes.OK},
		{"service other module", peer(t, "warden"), "ipam", false, codes.PermissionDenied},
		{"malformed module", gw, "Bad", false, codes.InvalidArgument},
	} {
		resp, err := check(c.ctx, c.module)
		if status.Code(err) != c.code {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if err == nil && resp.Allowed != c.allow {
			t.Errorf("%s: %+v", c.name, resp)
		}
	}
	// A custom role holding only warden:backup:manage: denied for ipam.
	if _, err := m.srv.RegisterPermissions(peer(t, "ipam"), &authv1.RegisterPermissionsRequest{Permissions: []*authv1.PermissionDef{{Resource: "backup", Action: "manage"}}}); err != nil {
		t.Fatal(err)
	}
	owner := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "owner", TenantID: tid, Roles: []string{"owner"}})
	r, err := m.srv.Roles.Create(owner, tid, "wb", "Warden backups", []string{"warden:backup:manage"})
	if err != nil {
		t.Fatal(err)
	}
	_ = m.ms.ReplaceBindings(context.Background(), tid, "u1", "", []string{"r-member", r.ID})
	fgaWrite(t, m, authz.RoleAssignmentTuple(tid, "wb", "u1"))
	batch, err := m.srv.BatchCheck(gw, &authv1.BatchCheckRequest{TenantId: tid, UserId: "u1", Permissions: []*authv1.PermissionRef{
		{Module: "warden", Resource: "backup", Action: "manage"}, {Module: "ipam", Resource: "backup", Action: "manage"}, {Resource: "backup", Action: "manage"}}})
	if err != nil || !batch.Results[0].Allowed || batch.Results[1].Allowed || batch.Results[2].Allowed || batch.Results[0].Reason != "role:wb" {
		t.Fatalf("%+v %v", batch, err)
	}
	if _, err := m.srv.BatchCheck(peer(t, "warden"), &authv1.BatchCheckRequest{TenantId: tid, UserId: "u1", Permissions: []*authv1.PermissionRef{{Module: "ipam", Resource: "backup", Action: "manage"}}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("service batch other module: %v", err)
	}
	if _, err := m.srv.BatchCheck(gw, &authv1.BatchCheckRequest{TenantId: tid, UserId: "u1", Permissions: []*authv1.PermissionRef{{Module: "warden", Resource: "a:b", Action: "c"}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("smuggled qualified ref: %v", err)
	}
	if _, err := m.srv.Check(gw, &authv1.CheckRequest{TenantId: tid, UserId: "u1", Resource: "warden:backup", Action: "manage"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("smuggled module in resource: %v", err)
	}
}

func fgaWrite(t *testing.T, m *modSrv, tuples ...authz.Tuple) {
	t.Helper()
	sys := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindSystem})
	if err := m.c.Write(sys, tid, tuples, nil); err != nil {
		t.Fatal(err)
	}
}
