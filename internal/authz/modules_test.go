package authz

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Feature 019 unit tests: module-scoped registration, the access-preserving
// migration (D3), legacy mirrors (D2), module roles (D4/D5) and built-in
// grants (D6), against the in-memory store and the OpenFGA fake.

// flakyFGA fails writes that match fail (once each) to test repair paths.
type flakyFGA struct {
	*Fake
	mu   sync.Mutex
	fail func(adds, removes []Tuple) bool
}

func (f *flakyFGA) Write(ctx context.Context, adds, removes []Tuple) error {
	f.mu.Lock()
	fail := f.fail
	if fail != nil && fail(adds, removes) {
		f.fail = nil
		f.mu.Unlock()
		return errors.New("fga unavailable")
	}
	f.mu.Unlock()
	return f.Fake.Write(ctx, adds, removes)
}

type modFixture struct {
	ms    *memstore.Store
	fga   *flakyFGA
	c     *Client
	kv    *cache.Memory
	reg   *Registry
	roles *Roles
	mods  *Modules
	dec   *Decider
	aw    *audit.Writer
	sys   context.Context
	owner context.Context
}

const tC = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"

// newModFixture builds tenant tA in its pre-019 state: legacy permissions
// backup:manage, stats:read, secrets:read and groups:manage; a custom role
// "backups" (legacy backup:manage) held by bob directly, a custom role
// "readers" (legacy stats:read) held by carol through a group, and a custom
// role named "operator" (the D6 gap). Tenant tB is an empty active tenant.
func newModFixture(t *testing.T) *modFixture {
	t.Helper()
	ctx := context.Background()
	ms := memstore.New()
	for _, id := range []string{tA, tB} {
		ms.AddTenant(store.Tenant{ID: id, Slug: "t-" + id[len(id)-2:], Status: "active", Kind: "customer", Policy: []byte("{}")})
		for _, slug := range []string{"owner", "admin", "member", "auditor"} {
			ms.AddRole(store.Role{ID: "r-" + slug + "-" + id[len(id)-2:], TenantID: id, Slug: slug, DisplayName: slug, Builtin: true})
		}
	}
	for _, u := range []string{"u-owner", "u-bob", "u-carol", "u-dave", "u-erin"} {
		ms.AddUser(store.User{ID: u, TenantID: tA, Email: u + "@x.test", Status: "active"})
	}
	ms.AddRole(store.Role{ID: "r-backups", TenantID: tA, Slug: "backups", DisplayName: "Backups"})
	ms.AddRole(store.Role{ID: "r-readers", TenantID: tA, Slug: "readers", DisplayName: "Readers"})
	ms.AddRole(store.Role{ID: "r-op", TenantID: tA, Slug: "operator", DisplayName: "Operator (custom)"})
	fga := &flakyFGA{Fake: NewFake()}
	kv := cache.NewMemory()
	c := New(fga, cache.New(kv), nil)
	aw := audit.NewWriter(ms, nil)
	t.Cleanup(aw.Close)
	f := &modFixture{ms: ms, fga: fga, c: c, kv: kv, aw: aw}
	f.reg = NewRegistry(ms, c, aw)
	f.roles = NewRoles(ms, c, NewEscalation(c), aw)
	f.mods = NewModules(ms, f.reg, f.roles, c, aw)
	f.mods.PlatformTenant = tA
	f.mods.Tenants = func(context.Context) ([]string, error) { return []string{tA, tB}, nil }
	f.dec = NewDecider(ms, c, aw)
	f.sys = tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	f.owner = tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", TenantID: tA, Roles: []string{"owner"}})
	// Pre-019 state of tenant A.
	legacy := []Permission{{Resource: "backup", Action: "manage"}, {Resource: "stats", Action: "read"}, {Resource: "secrets", Action: "read"}, {Resource: "groups", Action: "manage"}}
	for _, id := range []string{tA, tB} {
		if _, err := f.reg.Register(f.sys, id, "", "spiffe://td/svc/gateway", legacy); err != nil {
			t.Fatal(err)
		}
		for _, slug := range []string{"owner", "admin", "member", "auditor"} {
			if err := c.Write(f.sys, id, []Tuple{RoleTenantTuple(id, slug)}, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, slug := range []string{"backups", "readers", "operator"} {
		if err := c.Write(f.sys, tA, []Tuple{RoleTenantTuple(tA, slug)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	f.grant(t, "r-backups", PermissionRef{Resource: "backup", Action: "manage"})
	f.grant(t, "r-readers", PermissionRef{Resource: "stats", Action: "read"})
	f.grant(t, "r-admin-55", PermissionRef{Resource: "backup", Action: "manage"}, PermissionRef{Resource: "stats", Action: "read"})
	f.bind(t, "u-owner", "r-owner-55")
	f.bind(t, "u-bob", "r-backups")
	f.bind(t, "u-dave", "r-admin-55")
	// carol holds "readers" through a group.
	g := NewGroups(ms, c, aw)
	grp, err := g.Create(f.sys, tA, "Ops", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.SetRoles(f.sys, tA, grp.ID, []string{"r-readers"}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.AddMembers(f.sys, tA, grp.ID, []string{"u-carol"}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *modFixture) grant(t *testing.T, roleID string, refs ...PermissionRef) {
	t.Helper()
	ro, err := f.ms.Role(context.Background(), tA, roleID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.roles.addGrants(f.sys, tA, ro, refs); err != nil {
		t.Fatal(err)
	}
}

func (f *modFixture) bind(t *testing.T, uid, roleID string) {
	t.Helper()
	ro, _ := f.ms.Role(context.Background(), tA, roleID)
	have, _ := f.ms.UserRoles(context.Background(), tA, uid)
	ids := []string{roleID}
	for _, r := range have {
		ids = append(ids, r.ID)
	}
	if err := f.ms.ReplaceBindings(context.Background(), tA, uid, "", ids); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Write(f.sys, tA, []Tuple{RoleAssignmentTuple(tA, ro.Slug, uid)}, nil); err != nil {
		t.Fatal(err)
	}
}

func wardenReg(tenants ...string) Registration {
	return Registration{Module: "warden", DisplayName: "Warden", Registrant: "spiffe://td/svc/warden", Tenants: tenants,
		Permissions: []Permission{{Resource: "backup", Action: "manage"}, {Resource: "stats", Action: "read"}, {Resource: "secrets", Action: "read"}, {Resource: "secrets", Action: "write"}},
		Roles: []ModuleRole{
			{Slug: "administrator", DisplayName: "Warden administrator", Permissions: []string{"backup:manage", "stats:read", "secrets:read", "secrets:write"}},
			{Slug: "viewer", DisplayName: "Warden viewer", Description: "Read secrets", Permissions: []string{"secrets:read"}},
		},
		DeclaresRoles: true,
		Grants:        []BuiltinGrant{{Role: "admin", Permissions: []string{"backup:manage", "stats:read"}}, {Role: "auditor", Permissions: []string{"stats:read"}}, {Role: "operator", Permissions: []string{"backup:manage"}}},
	}
}

func ipamReg(tenants ...string) Registration {
	return Registration{Module: "ipam", DisplayName: "IPAM", Registrant: "spiffe://td/svc/ipam", Tenants: tenants,
		Permissions: []Permission{{Resource: "backup", Action: "manage"}, {Resource: "groups", Action: "manage"}, {Resource: "ipam", Action: "read"}}}
}

func (f *modFixture) allowed(t *testing.T, uid string, ref string) bool {
	t.Helper()
	p, err := ParsePermissionRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.dec.Decide(f.sys, tA, uid, p)
	if err != nil {
		t.Fatal(err)
	}
	return d.Allowed
}

func (f *modFixture) grants(t *testing.T, roleID string) []string {
	t.Helper()
	ps, err := f.ms.RolePermissions(context.Background(), tA, roleID)
	if err != nil {
		t.Fatal(err)
	}
	return refsOf(ps)
}

func (f *modFixture) events(typ audit.EventType) []map[string]any {
	f.aw.Flush()
	var out []map[string]any
	for _, r := range f.ms.AuditRows {
		if r.EventType == string(typ) {
			d := map[string]any{}
			_ = json.Unmarshal(r.Details, &d)
			d["_tenant"], d["_outcome"] = r.TenantID, r.Outcome
			out = append(out, d)
		}
	}
	return out
}

func (f *modFixture) roleBySlug(t *testing.T, tid, slug string) store.Role {
	t.Helper()
	roles, _ := f.ms.ListRoles(context.Background(), tid)
	for _, r := range roles {
		if r.Slug == slug {
			return r
		}
	}
	t.Fatalf("role %s missing in %s", slug, tid)
	return store.Role{}
}

// T016: the first scoped registration of each module grants module:res:act
// to every role holding the legacy res:act (direct and group-assigned),
// once; effective access before ⊆ after, gains only the per-module split.
func TestMigrationPreservesAccess(t *testing.T) {
	f := newModFixture(t)
	users := []string{"u-bob", "u-carol", "u-dave", "u-owner"}
	legacy := []string{"backup:manage", "stats:read", "secrets:read", "groups:manage"}
	before := map[string]bool{}
	for _, u := range users {
		for _, p := range legacy {
			before[u+" "+p] = f.allowed(t, u, p)
		}
	}
	if !before["u-bob backup:manage"] || !before["u-carol stats:read"] || before["u-bob stats:read"] {
		t.Fatalf("fixture: %v", before)
	}
	for i := 0; i < 2; i++ {
		if _, err := f.mods.Register(f.sys, wardenReg(tA)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.mods.Register(f.sys, ipamReg(tA)); err != nil {
			t.Fatal(err)
		}
	}
	// Every user keeps each legacy permission under every module registering it.
	for _, u := range users {
		for _, p := range legacy {
			for _, m := range []string{"warden", "ipam"} {
				scoped := m + ":" + p
				ipamLacks := m == "ipam" && (p == "stats:read" || p == "secrets:read")
				wardenLacks := m == "warden" && p == "groups:manage"
				if ipamLacks || wardenLacks {
					continue
				}
				if got := f.allowed(t, u, scoped); got != before[u+" "+p] {
					t.Errorf("%s %s: %v, before %v", u, scoped, got, before[u+" "+p])
				}
			}
			if got := f.allowed(t, u, p); got != before[u+" "+p] {
				t.Errorf("legacy %s %s changed: %v", u, p, got)
			}
		}
	}
	if got := f.grants(t, "r-backups"); !slices.Equal(got, []string{"backup:manage", "ipam:backup:manage", "warden:backup:manage"}) {
		t.Fatalf("backups grants %v", got)
	}
	if got := f.grants(t, "r-readers"); !slices.Equal(got, []string{"stats:read", "warden:stats:read"}) {
		t.Fatalf("readers grants %v", got)
	}
	// Audited once per tenant, module and role; the marker is set.
	if ev := f.events(audit.PermissionMigrated); len(ev) != 5 { // warden: admin, backups, readers; ipam: admin, backups
		t.Fatalf("permission_migrated %d: %v", len(ev), ev)
	}
	for _, m := range []string{"warden", "ipam"} {
		tm, err := f.ms.TenantModule(context.Background(), tA, m)
		if err != nil || tm.LegacyMigratedAt == nil {
			t.Fatalf("%s marker %+v %v", m, tm, err)
		}
	}
}

// T016: the marker is written only after the migration's tuple writes; a
// failed write leaves it unset and the next registration completes it.
func TestMigrationMarkerLast(t *testing.T) {
	f := newModFixture(t)
	f.fga.fail = func(adds, _ []Tuple) bool {
		for _, a := range adds {
			if a.User == RoleAssignees(tA, "backups") && strings.HasSuffix(a.Object, "/warden~backup~manage") {
				return true
			}
		}
		return false
	}
	if _, err := f.mods.Register(f.sys, wardenReg(tA)); err == nil {
		t.Fatal("registration succeeded despite the failed migration write")
	}
	if tm, _ := f.ms.TenantModule(context.Background(), tA, "warden"); tm.LegacyMigratedAt != nil {
		t.Fatal("marker set before the tuple write succeeded")
	}
	if f.allowed(t, "u-bob", "warden:backup:manage") {
		t.Fatal("grant exists without the write")
	}
	if _, err := f.mods.Register(f.sys, wardenReg(tA)); err != nil {
		t.Fatal(err)
	}
	if tm, _ := f.ms.TenantModule(context.Background(), tA, "warden"); tm.LegacyMigratedAt == nil {
		t.Fatal("marker not set after the retry")
	}
	if !f.allowed(t, "u-bob", "warden:backup:manage") {
		t.Fatal("retry did not migrate")
	}
	// A mirror write failing after the tuple write is repaired the same way.
	f.ms.FailNext("ReplaceRolePermissions")
	if _, err := f.mods.Register(f.sys, ipamReg(tA)); err == nil {
		t.Fatal("mirror failure hidden")
	}
	if _, err := f.mods.Register(f.sys, ipamReg(tA)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.grants(t, "r-backups"), "ipam:backup:manage") {
		t.Fatalf("mirror not repaired: %v", f.grants(t, "r-backups"))
	}
}

// T015 / SC-002: a permission of one module is refused in every other
// module; checks resolve scoped first and fall back to legacy only while the
// module has not registered the permission in the tenant.
func TestCrossModuleDenialAndFallback(t *testing.T) {
	f := newModFixture(t)
	// Before any scoped registration: a scoped check falls back to legacy.
	if !f.allowed(t, "u-bob", "warden:backup:manage") || f.allowed(t, "u-bob", "warden:stats:read") {
		t.Fatal("legacy fallback")
	}
	if _, err := f.mods.Register(f.sys, wardenReg(tA)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.mods.Register(f.sys, Registration{Module: "lcm", Registrant: "spiffe://td/svc/lcm", Tenants: []string{tA}, Permissions: []Permission{{Resource: "stats", Action: "read"}}}); err != nil {
		t.Fatal(err)
	}
	role, err := f.roles.Create(f.owner, tA, "warden-backups", "Warden backups", []string{"warden:backup:manage", "warden:stats:read"})
	if err != nil {
		t.Fatal(err)
	}
	f.bind(t, "u-erin", role.ID)
	if !f.allowed(t, "u-erin", "warden:backup:manage") {
		t.Fatal("own module refused")
	}
	// ipam has not registered in the tenant: its legacy fallback does not
	// know erin (she holds no legacy backup:manage).
	if f.allowed(t, "u-erin", "ipam:backup:manage") {
		t.Fatal("cross-module bleed through the legacy fallback")
	}
	if _, err := f.mods.Register(f.sys, ipamReg(tA)); err != nil {
		t.Fatal(err)
	}
	if f.allowed(t, "u-erin", "ipam:backup:manage") {
		t.Fatal("warden permission granted ipam backups")
	}
	if f.allowed(t, "u-erin", "lcm:stats:read") {
		t.Fatal("warden stats granted lcm stats")
	}
	// Unknown in scope and legacy: unknown_permission.
	d, _ := f.dec.Decide(f.sys, tA, "u-erin", PermissionRef{Module: "dns", Resource: "zones", Action: "read"})
	if d.Allowed || d.Reason != ReasonUnknownPermission {
		t.Fatalf("%+v", d)
	}
	// Scoped and legacy decisions are cached under different keys: carol
	// holds warden:backup:manage, not the legacy object.
	for i := 0; i < 2; i++ {
		if !f.allowed(t, "u-erin", "warden:backup:manage") || f.allowed(t, "u-erin", "backup:manage") {
			t.Fatal("scoped and legacy decisions crossed")
		}
	}
	v, _ := f.c.cache.TenantVersion(context.Background(), tA)
	for _, k := range []string{"warden:backup:manage", "backup:manage"} {
		if _, ok, _ := f.kv.Get(context.Background(), cache.DecisionKey(tA, "u-erin", k+"@"+itoa(v))); !ok {
			t.Fatalf("decision key for %s missing", k)
		}
	}
	// In-process check (auth's own routes) resolves the same way.
	if ok, err := f.dec.Allowed(f.sys, tA, "u-bob", PermissionRef{Module: "ipam", Resource: "groups", Action: "manage"}); err != nil || ok {
		t.Fatalf("bob ipam groups: %v %v", ok, err)
	}
	if ok, _ := f.dec.Allowed(f.sys, tA, "u-bob", PermissionRef{Module: "nope", Resource: "x", Action: "y"}); ok {
		t.Fatal("unknown permission allowed in-process")
	}
}

func itoa(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// T017: built-in grants are mirrored to the legacy object while it exists;
// module and custom roles never are; after prune nothing is written legacy.
func TestLegacyMirrorOfBuiltinGrants(t *testing.T) {
	f := newModFixture(t)
	if _, err := f.mods.Register(f.sys, wardenReg(tA, tB)); err != nil {
		t.Fatal(err)
	}
	adminB := f.roleBySlug(t, tB, "admin")
	got, _ := f.ms.RolePermissions(context.Background(), tB, adminB.ID)
	if !slices.Equal(refsOf(got), []string{"backup:manage", "stats:read", "warden:backup:manage", "warden:stats:read"}) {
		t.Fatalf("admin (tB) %v", refsOf(got))
	}
	viewer := f.roleBySlug(t, tA, "m.warden.viewer")
	if got := f.grants(t, viewer.ID); !slices.Equal(got, []string{"warden:secrets:read"}) {
		t.Fatalf("module role got legacy grants: %v", got)
	}
	// Prune tB's legacy rows; the next registration writes no legacy grant.
	if _, err := f.ms.DeleteLegacyPermissions(context.Background(), tB); err != nil {
		t.Fatal(err)
	}
	auditorB := f.roleBySlug(t, tB, "auditor")
	if _, err := f.mods.Register(f.sys, wardenReg(tB)); err != nil {
		t.Fatal(err)
	}
	got, _ = f.ms.RolePermissions(context.Background(), tB, auditorB.ID)
	if !slices.Equal(refsOf(got), []string{"warden:stats:read"}) {
		t.Fatalf("auditor after prune %v", refsOf(got))
	}
}

// T038: module roles exist in every tenant with exactly their permissions,
// follow definition changes, retire and come back, and never lose
// assignments; rejected roles are reported individually.
func TestModuleRoles(t *testing.T) {
	f := newModFixture(t)
	res, err := f.mods.Register(f.sys, wardenReg(tA, tB))
	if err != nil || res.RolesUpserted != 2 || len(res.RoleErrors) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, tid := range []string{tA, tB} {
		v := f.roleBySlug(t, tid, "m.warden.viewer")
		if v.OriginOf() != store.OriginModule || v.Module != "warden" || v.ModuleSlug != "viewer" || v.DisplayName != "Warden viewer" || v.Description != "Read secrets" || v.Builtin {
			t.Fatalf("%+v", v)
		}
		got, _ := f.ms.RolePermissions(context.Background(), tid, v.ID)
		if !slices.Equal(refsOf(got), []string{"warden:secrets:read"}) {
			t.Fatalf("%s viewer %v", tid, refsOf(got))
		}
		if ok, _ := f.fga.Check(context.Background(), RoleTenantTuple(tid, "m.warden.viewer")); !ok {
			t.Fatal("role tenant tuple")
		}
	}
	viewer := f.roleBySlug(t, tA, "m.warden.viewer")
	f.bind(t, "u-carol", viewer.ID)
	if !f.allowed(t, "u-carol", "warden:secrets:read") || f.allowed(t, "u-carol", "warden:secrets:write") {
		t.Fatal("viewer grants")
	}
	// Idempotent: nothing changes, nothing upserted.
	if res, err := f.mods.Register(f.sys, wardenReg(tA, tB)); err != nil || res.RolesUpserted != 0 || len(res.RolesRetired) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	// A new version widens the viewer: every tenant follows, assignment kept.
	reg := wardenReg(tA, tB)
	reg.Roles[1].Permissions = []string{"secrets:read", "stats:read"}
	reg.Roles[1].DisplayName = "Warden reader"
	if res, err := f.mods.Register(f.sys, reg); err != nil || res.RolesUpserted != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if !f.allowed(t, "u-carol", "warden:stats:read") || f.roleBySlug(t, tB, "m.warden.viewer").DisplayName != "Warden reader" {
		t.Fatal("definition change not applied")
	}
	// Dropping the viewer retires it everywhere; assignments and grants stay.
	reg.Roles = reg.Roles[:1]
	res, err = f.mods.Register(f.sys, reg)
	if err != nil || !slices.Equal(res.RolesRetired, []string{"viewer"}) {
		t.Fatalf("%+v %v", res, err)
	}
	if r := f.roleBySlug(t, tA, "m.warden.viewer"); r.RetiredAt == nil {
		t.Fatal("not retired")
	}
	if !f.allowed(t, "u-carol", "warden:secrets:read") {
		t.Fatal("retirement removed access")
	}
	if ev := f.events(audit.ModuleRoleRetired); len(ev) != 1 || ev[0]["slug"] != "viewer" || ev[0]["assignments_kept"] != float64(1) {
		t.Fatalf("module_role_retired %v", ev)
	}
	// A new tenant registered after retirement does not get the retired role.
	f.ms.AddTenant(store.Tenant{ID: tC, Slug: "t-c", Status: "active", Kind: "customer", Policy: []byte("{}")})
	if _, err := f.mods.Register(f.sys, wardenReg(tC)); err != nil { // declares viewer again → un-retired
		t.Fatal(err)
	}
	if r := f.roleBySlug(t, tA, "m.warden.viewer"); r.RetiredAt != nil {
		// tA was not in this registration: its copy follows at its next registration.
		t.Log("tA copy still retired until its next registration")
	}
	if _, err := f.mods.Register(f.sys, wardenReg(tA)); err != nil {
		t.Fatal(err)
	}
	if r := f.roleBySlug(t, tA, "m.warden.viewer"); r.RetiredAt != nil {
		t.Fatal("re-declared role still retired")
	}
	if ev := f.events(audit.ModuleRoleUpserted); len(ev) < 3 {
		t.Fatalf("module_role_upserted %v", ev)
	}
	if ev := f.events(audit.ModuleRegistered); len(ev) == 0 || ev[0]["module"] != "warden" || ev[0]["_tenant"] != tA {
		t.Fatalf("module_registered %v", ev)
	}
}

// T038 negative: roles naming another module's or an unregistered
// permission, bad slugs and names, too many or no permissions and duplicates
// are rejected one by one; the valid roles still apply.
func TestModuleRoleErrors(t *testing.T) {
	f := newModFixture(t)
	many := make([]string, 0, 201)
	for i := 0; i < 201; i++ {
		many = append(many, "secrets:read")
	}
	reg := wardenReg(tA)
	reg.Roles = append(reg.Roles,
		ModuleRole{Slug: "thief", DisplayName: "Thief", Permissions: []string{"ipam:backup:manage"}},
		ModuleRole{Slug: "wide", DisplayName: "Wide", Permissions: []string{"users:manage"}},
		ModuleRole{Slug: "Bad.Slug", DisplayName: "Bad", Permissions: []string{"secrets:read"}},
		ModuleRole{Slug: "noname", DisplayName: " ", Permissions: []string{"secrets:read"}},
		ModuleRole{Slug: "ctrl", DisplayName: "Ctrl\x07", Permissions: []string{"secrets:read"}},
		ModuleRole{Slug: "huge", DisplayName: "Huge", Permissions: many},
		ModuleRole{Slug: "empty", DisplayName: "Empty"},
		ModuleRole{Slug: "viewer", DisplayName: "Second viewer", Permissions: []string{"secrets:write"}},
		ModuleRole{Slug: "qualified", DisplayName: "Qualified", Permissions: []string{"warden:secrets:read"}},
	)
	res, err := f.mods.Register(f.sys, reg)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"thief": RoleForeignPermission, "wide": RoleForeignPermission, "Bad.Slug": RoleInvalidSlug, "noname": RoleInvalidName, "ctrl": RoleInvalidName,
		"huge": RoleTooManyPerms, "empty": RoleNoPermissions, "viewer": RoleDuplicate}
	if len(res.RoleErrors) != len(want) {
		t.Fatalf("%+v", res.RoleErrors)
	}
	for _, e := range res.RoleErrors {
		if want[e.Slug] != e.Reason {
			t.Errorf("%s: %s, want %s", e.Slug, e.Reason, want[e.Slug])
		}
	}
	for _, slug := range []string{"m.warden.administrator", "m.warden.viewer", "m.warden.qualified"} {
		f.roleBySlug(t, tA, slug)
	}
	roles, _ := f.ms.ListRoles(context.Background(), tA)
	for _, r := range roles {
		if r.Slug == "m.warden.thief" || r.Slug == "m.warden.wide" {
			t.Fatalf("rejected role created: %s", r.Slug)
		}
		if r.Module == "warden" {
			for _, p := range f.grants(t, r.ID) {
				if !strings.HasPrefix(p, "warden:") {
					t.Fatalf("module role %s holds %s", r.Slug, p)
				}
			}
		}
	}
	// Whole-registration refusals.
	for name, mut := range map[string]func(*Registration){
		"module":      func(r *Registration) { r.Module = "Warden" },
		"display":     func(r *Registration) { r.DisplayName = strings.Repeat("x", 121) },
		"permission":  func(r *Registration) { r.Permissions = append(r.Permissions, Permission{Resource: "Bad", Action: "x"}) },
		"description": func(r *Registration) { r.Permissions[0].Description = strings.Repeat("d", 257) },
		"too many":    func(r *Registration) { r.Permissions = make([]Permission, 201) },
		"too roles":   func(r *Registration) { r.Roles = make([]ModuleRole, 21) },
		"grant role": func(r *Registration) {
			r.Grants = []BuiltinGrant{{Role: "backups", Permissions: []string{"backup:manage"}}}
		},
		"grant perm": func(r *Registration) {
			r.Grants = []BuiltinGrant{{Role: "admin", Permissions: []string{"users:manage"}}}
		},
		"tenant":       func(r *Registration) { r.Tenants = []string{"nope"} },
		"delegate":     func(r *Registration) { r.Delegate = "gateway" },
		"delegate dec": func(r *Registration) { r.Delegate, r.Roles, r.Grants = "gateway", nil, nil },
	} {
		r := wardenReg(tA)
		mut(&r)
		if name == "delegate dec" {
			if _, err := f.mods.Register(f.sys, r); !errors.Is(err, ErrBadRegistration) {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if _, err := f.mods.Register(f.sys, r); !errors.Is(err, ErrBadRegistration) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// T014 (authz part): a delegated registration refreshes the module's
// permissions (and runs the migration) but never touches roles or grants.
func TestDelegatedRegistration(t *testing.T) {
	f := newModFixture(t)
	reg := ipamReg(tA)
	reg.Delegate, reg.Registrant = "gateway", "spiffe://td/svc/gateway"
	if _, err := f.mods.Register(f.sys, reg); err != nil {
		t.Fatal(err)
	}
	if !f.allowed(t, "u-bob", "ipam:backup:manage") {
		t.Fatal("delegated registration did not migrate")
	}
	if got := f.grants(t, "r-backups"); !slices.Contains(got, "ipam:backup:manage") {
		t.Fatalf("%v", got)
	}
	roles, _ := f.ms.ListRoles(context.Background(), tA)
	for _, r := range roles {
		if r.Module != "" {
			t.Fatalf("delegated registration created %s", r.Slug)
		}
	}
	if ev := f.events(audit.ModuleRegistered); len(ev) != 1 || ev[0]["delegate"] != "gateway" {
		t.Fatalf("%v", ev)
	}
}

// T069/T070: built-in grants only reach roles with origin builtin; a custom
// role named "operator" gets nothing; missing built-in roles are reported
// with a count and at most five sample tenants.
func TestBuiltinGrantsReportedNotLost(t *testing.T) {
	f := newModFixture(t)
	tenants := []string{tA, tB}
	for i := 0; i < 6; i++ {
		id := "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4d0" + string(rune('0'+i))
		f.ms.AddTenant(store.Tenant{ID: id, Slug: "x" + id[len(id)-1:], Status: "active", Kind: "customer", Policy: []byte("{}")})
		tenants = append(tenants, id)
	}
	res, err := f.mods.Register(f.sys, wardenReg(tenants...))
	if err != nil {
		t.Fatal(err)
	}
	// operator: no tenant has the built-in role; auditor: the 6 new tenants lack it; admin likewise.
	byRole := map[string]SkippedGrant{}
	for _, s := range res.Skipped {
		byRole[s.Role] = s
	}
	if op := byRole["operator"]; op.Tenants != 8 || len(op.Sample) != MaxSkippedSamples || op.Reason != SkipRoleMissing {
		t.Fatalf("operator %+v", op)
	}
	if au := byRole["auditor"]; au.Tenants != 6 || len(au.Sample) != 5 {
		t.Fatalf("auditor %+v", au)
	}
	if got := f.grants(t, "r-op"); len(got) != 0 {
		t.Fatalf("custom operator received module grants: %v", got)
	}
	if got := f.grants(t, "r-auditor-55"); !slices.Contains(got, "warden:stats:read") {
		t.Fatalf("auditor grants %v", got)
	}
}

// T039 (authz part): a new tenant receives every non-retired module
// permission and role of the catalogue without a re-registration.
func TestInstantiateTenant(t *testing.T) {
	f := newModFixture(t)
	if _, err := f.mods.Register(f.sys, wardenReg(tA)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.mods.Register(f.sys, Registration{Module: "gone", Registrant: "spiffe://td/svc/gone", Tenants: []string{tA}, Permissions: []Permission{{Resource: "x", Action: "y"}},
		Roles: []ModuleRole{{Slug: "user", DisplayName: "Gone user", Permissions: []string{"x:y"}}}, DeclaresRoles: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.mods.RetireModule(f.sys, "gone"); err != nil {
		t.Fatal(err)
	}
	f.ms.AddTenant(store.Tenant{ID: tC, Slug: "t-c", Status: "active", Kind: "customer", Policy: []byte("{}")})
	if err := f.mods.InstantiateTenant(context.Background(), tC); err != nil {
		t.Fatal(err)
	}
	perms, _ := f.ms.ListPermissions(context.Background(), tC)
	var refs []string
	for _, p := range perms {
		refs = append(refs, p.Ref().String())
	}
	if !slices.Equal(refs, []string{"warden:backup:manage", "warden:secrets:read", "warden:secrets:write", "warden:stats:read"}) {
		t.Fatalf("%v", refs)
	}
	roles, _ := f.ms.ListRoles(context.Background(), tC)
	var slugs []string
	for _, r := range roles {
		slugs = append(slugs, r.Slug)
	}
	if !slices.Equal(slugs, []string{"m.warden.administrator", "m.warden.viewer"}) {
		t.Fatalf("%v", slugs)
	}
	if tm, err := f.ms.TenantModule(context.Background(), tC, "warden"); err != nil || tm.LegacyMigratedAt == nil {
		t.Fatalf("%+v %v", tm, err)
	}
}

// T042: retiring a module retires its roles in every tenant (grants and
// assignments kept) and hides its permissions from the editor.
func TestRetireModule(t *testing.T) {
	f := newModFixture(t)
	if _, err := f.mods.Register(f.sys, wardenReg(tA, tB)); err != nil {
		t.Fatal(err)
	}
	viewer := f.roleBySlug(t, tA, "m.warden.viewer")
	f.bind(t, "u-carol", viewer.ID)
	slugs, err := f.mods.RetireModule(f.sys, "warden")
	if err != nil || !slices.Equal(slugs, []string{"administrator", "viewer"}) {
		t.Fatalf("%v %v", slugs, err)
	}
	for _, tid := range []string{tA, tB} {
		if r := f.roleBySlug(t, tid, "m.warden.viewer"); r.RetiredAt == nil {
			t.Fatalf("%s viewer not retired", tid)
		}
	}
	if !f.allowed(t, "u-carol", "warden:secrets:read") {
		t.Fatal("retirement removed access")
	}
	cat, err := f.reg.Catalogue(f.sys, tA, tenantctx.Actor{Kind: tenantctx.KindSystem})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range cat {
		if e.Module == "warden" {
			t.Fatalf("retired module listed: %+v", e)
		}
	}
	if _, err := f.mods.RetireModule(f.sys, "nope"); !errors.Is(err, ErrUnknownModule) {
		t.Fatalf("unknown module: %v", err)
	}
	if ev := f.events(audit.ModuleRoleRetired); len(ev) != 2 {
		t.Fatalf("%v", ev)
	}
}

// T064 (authz part): the catalogue carries module display names, sorts by
// them (legacy last) and computes grantable for the actor.
func TestCatalogue(t *testing.T) {
	f := newModFixture(t)
	for _, r := range []Registration{wardenReg(tA), ipamReg(tA), {Module: AuthModule, DisplayName: AuthDisplayName, Registrant: "auth", Tenants: []string{tA}, Permissions: []Permission{{Resource: "users", Action: "manage"}}}} {
		if _, err := f.mods.Register(f.sys, r); err != nil {
			t.Fatal(err)
		}
	}
	cat, err := f.reg.Catalogue(f.owner, tA, tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-owner", Roles: []string{"owner"}})
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, e := range cat {
		if !e.Grantable {
			t.Fatalf("owner cannot grant %s", e.Ref)
		}
		if len(order) == 0 || order[len(order)-1] != e.ModuleDisplayName {
			order = append(order, e.ModuleDisplayName)
		}
	}
	if !slices.Equal(order, []string{"Authentication", "IPAM", "Warden", LegacyDisplayName}) {
		t.Fatalf("%v", order)
	}
	// bob holds backup:manage (legacy and migrated) only.
	cat, err = f.reg.Catalogue(f.owner, tA, tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u-bob"})
	if err != nil {
		t.Fatal(err)
	}
	var grantable []string
	for _, e := range cat {
		if e.Grantable {
			grantable = append(grantable, e.Ref)
		}
		if e.Legacy != (e.Module == "") || (e.Legacy && e.ModuleDisplayName != LegacyDisplayName) {
			t.Fatalf("%+v", e)
		}
	}
	if !slices.Equal(grantable, []string{"ipam:backup:manage", "warden:backup:manage", "backup:manage"}) {
		t.Fatalf("%v", grantable)
	}
}
