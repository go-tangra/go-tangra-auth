package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

const cliTenant = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

type cliFixture struct {
	ms   *memstore.Store
	mods *authz.Modules
	cli  PermissionsCLI
	out  *bytes.Buffer
	sys  context.Context
}

// newCLIFixture: one tenant in its pre-019 state, a custom role "backups"
// holding legacy backup:manage, held by bob.
func newCLIFixture(t *testing.T) *cliFixture {
	t.Helper()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: cliTenant, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u-bob", TenantID: cliTenant, Email: "bob@x.test", Status: "active"})
	ms.AddRole(store.Role{ID: "r-backups", TenantID: cliTenant, Slug: "backups", DisplayName: "Backups"})
	c := authz.New(authz.NewFake(), cache.New(cache.NewMemory()), nil)
	reg := authz.NewRegistry(ms, c, nil)
	roles := authz.NewRoles(ms, c, authz.NewEscalation(c), nil)
	mods := authz.NewModules(ms, reg, roles, c, nil)
	sys := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindSystem})
	if _, err := reg.Register(sys, cliTenant, "", "gw", []authz.Permission{{Resource: "backup", Action: "manage"}}); err != nil {
		t.Fatal(err)
	}
	legacy := authz.PermissionRef{Resource: "backup", Action: "manage"}
	if err := c.Write(sys, cliTenant, []authz.Tuple{authz.RoleTenantTuple(cliTenant, "backups"), authz.GrantTuple(cliTenant, "backups", legacy), authz.RoleAssignmentTuple(cliTenant, "backups", "u-bob")}, nil); err != nil {
		t.Fatal(err)
	}
	_ = ms.ReplaceRolePermissions(context.Background(), cliTenant, "r-backups", []authz.PermissionRef{legacy})
	_ = ms.ReplaceBindings(context.Background(), cliTenant, "u-bob", "", []string{"r-backups"})
	out := &bytes.Buffer{}
	return &cliFixture{ms: ms, mods: mods, out: out, sys: sys, cli: PermissionsCLI{V: authz.NewVerifier(ms, c, nil), Modules: mods, Out: out,
		Tenants: func(context.Context) ([]string, error) { return []string{cliTenant}, nil }}}
}

func (f *cliFixture) register(t *testing.T) {
	t.Helper()
	if _, err := f.mods.Register(f.sys, authz.Registration{Module: "warden", Registrant: "spiffe://td/svc/warden", Tenants: []string{cliTenant},
		Permissions: []authz.Permission{{Resource: "backup", Action: "manage"}}}); err != nil {
		t.Fatal(err)
	}
}

// T018: verify prints a JSON report and exits 1 on a loss; snapshot and
// compare round-trip through a file; prune-legacy refuses until verify is
// clean, supports a dry run, then prunes.
func TestPermissionsCLI(t *testing.T) {
	f := newCLIFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	snap := filepath.Join(dir, "before.json")
	if code, err := f.cli.Verify(ctx, "", snap, ""); err != nil || code != 0 {
		t.Fatalf("snapshot: %d %v", code, err)
	}
	if fi, err := os.Stat(snap); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot file: %v %v", fi, err)
	}
	// Pending grants: verify exits 0 (no loss) but prune refuses.
	f.out.Reset()
	if code, err := f.cli.Verify(ctx, "", "", ""); err != nil || code != 0 || !strings.Contains(f.out.String(), `"pending"`) {
		t.Fatalf("%d %v %s", code, err, f.out.String())
	}
	if code, err := f.cli.Prune(ctx, false); err != nil || code != 1 {
		t.Fatalf("prune with pending: %d %v", code, err)
	}
	f.register(t)
	f.out.Reset()
	if code, err := f.cli.Verify(ctx, cliTenant, "", snap); err != nil || code != 0 {
		t.Fatalf("compare: %d %v %s", code, err, f.out.String())
	}
	var rep authz.Report
	if err := json.Unmarshal(f.out.Bytes(), &rep); err != nil || rep.Losses() != 0 || rep.Tenants != 1 {
		t.Fatalf("%v %+v", err, rep)
	}
	// A lost scoped grant: verify exits 1.
	_ = f.ms.ReplaceRolePermissions(ctx, cliTenant, "r-backups", []authz.PermissionRef{{Resource: "backup", Action: "manage"}})
	if code, _ := f.cli.Verify(ctx, "", "", ""); code != 1 {
		t.Fatal("loss not reported with exit status 1")
	}
	if code, _ := f.cli.Prune(ctx, true); code != 1 {
		t.Fatal("dry run accepted a loss")
	}
	_ = f.ms.ReplaceRolePermissions(ctx, cliTenant, "r-backups", []authz.PermissionRef{{Resource: "backup", Action: "manage"}, {Module: "warden", Resource: "backup", Action: "manage"}})
	f.out.Reset()
	if code, err := f.cli.Prune(ctx, true); err != nil || code != 0 || !strings.Contains(f.out.String(), `"permissions": 1`) || !strings.Contains(f.out.String(), `"dry_run": true`) {
		t.Fatalf("dry run: %d %v %s", code, err, f.out.String())
	}
	if code, err := f.cli.Prune(ctx, false); err != nil || code != 0 {
		t.Fatalf("prune: %d %v %s", code, err, f.out.String())
	}
	perms, _ := f.ms.ListPermissions(ctx, cliTenant)
	if len(perms) != 1 || perms[0].Module != "warden" {
		t.Fatalf("%+v", perms)
	}
	// The snapshot still compares clean after prune.
	if code, _ := f.cli.Verify(ctx, "", "", snap); code != 0 {
		t.Fatalf("compare after prune: %s", f.out.String())
	}
	// Errors: unreadable snapshot, unknown tenant id format.
	if _, err := f.cli.Verify(ctx, "", "", filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing snapshot accepted")
	}
	if _, err := f.cli.Verify(ctx, "not-a-uuid", "", ""); err == nil {
		t.Fatal("malformed tenant accepted")
	}
}

// T042/T050: modules retire prints the retired roles; unknown modules fail.
func TestModulesRetireCLI(t *testing.T) {
	f := newCLIFixture(t)
	if _, err := f.mods.Register(f.sys, authz.Registration{Module: "warden", Registrant: "spiffe://td/svc/warden", Tenants: []string{cliTenant},
		Permissions: []authz.Permission{{Resource: "secrets", Action: "read"}}, Roles: []authz.ModuleRole{{Slug: "viewer", DisplayName: "Warden viewer", Permissions: []string{"secrets:read"}}}, DeclaresRoles: true}); err != nil {
		t.Fatal(err)
	}
	f.mods.Tenants = f.cli.Tenants
	if code, err := f.cli.RetireModule(context.Background(), "warden"); err != nil || code != 0 || !strings.Contains(f.out.String(), `"viewer"`) {
		t.Fatalf("%d %v %s", code, err, f.out.String())
	}
	if code, err := f.cli.RetireModule(context.Background(), "nope"); err == nil || code == 0 {
		t.Fatal("unknown module retired")
	}
	if code, err := f.cli.RetireModule(context.Background(), "Bad Name"); err == nil || code == 0 {
		t.Fatal("malformed module accepted")
	}
}
