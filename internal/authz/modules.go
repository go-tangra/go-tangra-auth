package authz

import (
	"context"
	"errors"
	"sort"
	"strings"
	"unicode"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/permref"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Registration limits (feature 019, research D11).
const (
	MaxRegistrationPermissions = 200
	MaxModuleRoles             = 20
	MaxRolePermissions         = 200
	MaxSkippedSamples          = 5
)

// Role error reasons of a registration (auth.v1.RoleError.reason).
const (
	RoleInvalidSlug       = "invalid_slug"
	RoleInvalidName       = "invalid_name"
	RoleForeignPermission = "foreign_permission"
	RoleTooManyPerms      = "too_many_permissions"
	RoleNoPermissions     = "no_permissions"
	RoleDuplicate         = "duplicate"
)

// SkipRoleMissing is the reason of a built-in grant whose role a tenant lacks.
const SkipRoleMissing = "role_missing"

// BuiltinRoleSlugs are the roles built-in grants may target.
var BuiltinRoleSlugs = map[string]bool{"owner": true, "admin": true, "member": true, "auditor": true, "operator": true}

// ErrBadRegistration refuses a registration as a whole (limits, grammar,
// grants outside the request or to a non-built-in role).
var ErrBadRegistration = errors.New("authz: invalid registration")

// ModuleStore is the platform catalogue and per-tenant module state.
type ModuleStore interface {
	UpsertModule(ctx context.Context, name, displayName string) error
	Modules(ctx context.Context) ([]store.Module, error)
	RetireModule(ctx context.Context, name string) error
	UpsertModulePermission(ctx context.Context, p store.ModulePermission) error
	ModulePermissions(ctx context.Context, module string) ([]store.ModulePermission, error)
	UpsertModuleRoleDef(ctx context.Context, d store.ModuleRoleDef) (bool, error)
	ModuleRoleDefs(ctx context.Context, module string) ([]store.ModuleRoleDef, error)
	RetireModuleRoleDef(ctx context.Context, module, slug string) error
	TenantModule(ctx context.Context, tenantID, module string) (store.TenantModule, error)
	EnsureTenantModule(ctx context.Context, tenantID, module string) error
	MarkLegacyMigrated(ctx context.Context, tenantID, module string) error
}

// ModuleRole is a role a module declares: slug, display name, description
// and "resource:action" permissions of the same registration.
type ModuleRole struct {
	Slug, DisplayName, Description string
	Permissions                    []string
}

// BuiltinGrant grants short "resource:action" refs of the registration to a
// built-in role in every tenant.
type BuiltinGrant struct {
	Role        string
	Permissions []string
}

// Registration is one module's registration (feature 019).
type Registration struct {
	Module, DisplayName string
	Registrant          string // caller identity, recorded on the rows
	Delegate            string // "gateway" for a delegated registration
	Permissions         []Permission
	Roles               []ModuleRole
	DeclaresRoles       bool
	Grants              []BuiltinGrant
	Tenants             []string
}

// SkippedGrant reports a built-in grant that found no role in some tenants.
type SkippedGrant struct {
	Role    string
	Tenants int
	Sample  []string
	Reason  string
}

// RoleError names a declared role the registration refused.
type RoleError struct{ Slug, Reason string }

// RegisterResult is the outcome of a registration.
type RegisterResult struct {
	Registered    int
	Skipped       []SkippedGrant
	RoleErrors    []RoleError
	RolesUpserted int
	RolesRetired  []string
}

// Modules owns module registration: the platform catalogue, module-scoped
// permissions in every tenant, the access-preserving migration of legacy
// grants (D3), module roles (D4/D5) and built-in grants (D6).
type Modules struct {
	st    ModuleStore
	reg   *Registry
	roles *Roles
	authz *Client
	audit *audit.Writer
	// PlatformTenant receives the platform-wide audit events
	// (module_registered, module_role_upserted, module_role_retired).
	PlatformTenant string
	// Tenants lists every active tenant (module retirement).
	Tenants func(ctx context.Context) ([]string, error)
}

// NewModules wires the service.
func NewModules(st ModuleStore, reg *Registry, roles *Roles, c *Client, a *audit.Writer) *Modules {
	return &Modules{st: st, reg: reg, roles: roles, authz: c, audit: a}
}

func printable(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// validate checks the registration as a whole and each declared role; it
// returns the accepted role definitions (short refs, sorted) and the
// individual role errors.
func (reg Registration) validate() ([]store.ModuleRoleDef, []RoleError, error) {
	if !permref.ValidModule(reg.Module) || !printable(reg.DisplayName, 120) || strings.TrimSpace(reg.DisplayName) != reg.DisplayName {
		return nil, nil, ErrBadRegistration
	}
	if len(reg.Permissions) > MaxRegistrationPermissions || len(reg.Roles) > MaxModuleRoles {
		return nil, nil, ErrBadRegistration
	}
	own := map[string]bool{}
	for _, p := range reg.Permissions {
		if !permref.ValidResource(p.Resource) || !permref.ValidAction(p.Action) || !printable(p.Description, 256) {
			return nil, nil, ErrBadRegistration
		}
		own[p.Resource+":"+p.Action] = true
	}
	for _, g := range reg.Grants {
		if !BuiltinRoleSlugs[g.Role] {
			return nil, nil, ErrBadRegistration
		}
		for _, s := range g.Permissions {
			if !own[s] {
				return nil, nil, ErrBadRegistration
			}
		}
	}
	var defs []store.ModuleRoleDef
	var errs []RoleError
	seen := map[string]bool{}
	for _, r := range reg.Roles {
		reason := ""
		name := strings.TrimSpace(r.DisplayName)
		var perms []string
		switch {
		case !permref.ValidRoleDefSlug(r.Slug):
			reason = RoleInvalidSlug
		case seen[r.Slug]:
			reason = RoleDuplicate
		case name == "" || !printable(name, 120) || !printable(r.Description, 256):
			reason = RoleInvalidName
		case len(r.Permissions) == 0:
			reason = RoleNoPermissions
		case len(r.Permissions) > MaxRolePermissions:
			reason = RoleTooManyPerms
		default:
			set := map[string]bool{}
			for _, s := range r.Permissions {
				short := s
				if ref, err := permref.Parse(s); err == nil && ref.Module == reg.Module {
					short = ref.Short()
				}
				if !own[short] {
					reason = RoleForeignPermission
					break
				}
				if !set[short] {
					set[short] = true
					perms = append(perms, short)
				}
			}
		}
		seen[r.Slug] = true
		if reason != "" {
			errs = append(errs, RoleError{Slug: r.Slug, Reason: reason})
			continue
		}
		sort.Strings(perms)
		defs = append(defs, store.ModuleRoleDef{Module: reg.Module, Slug: r.Slug, DisplayName: name, Description: r.Description, Permissions: perms})
	}
	return defs, errs, nil
}

// Register applies a module registration: catalogue, then every tenant
// (permissions, first-registration migration of legacy grants, module roles,
// built-in grants). A delegated registration (the gateway) may not carry
// roles or grants. Rejected roles are reported, not fatal.
func (m *Modules) Register(ctx context.Context, reg Registration) (RegisterResult, error) {
	var res RegisterResult
	defs, roleErrs, err := reg.validate()
	if err != nil {
		return res, err
	}
	if reg.Delegate != "" && (len(reg.Roles) > 0 || reg.DeclaresRoles || len(reg.Grants) > 0) {
		return res, ErrBadRegistration
	}
	res.RoleErrors = roleErrs
	for _, t := range reg.Tenants {
		if !tenantctx.ValidTenantID(t) {
			return res, ErrBadRegistration
		}
	}
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	// Catalogue.
	if err := m.st.UpsertModule(sys, reg.Module, reg.DisplayName); err != nil {
		return res, err
	}
	for _, p := range reg.Permissions {
		if err := m.st.UpsertModulePermission(sys, store.ModulePermission{Module: reg.Module, Resource: p.Resource, Action: p.Action, Description: p.Description}); err != nil {
			return res, err
		}
	}
	var upserted, retired []store.ModuleRoleDef
	if reg.Delegate == "" {
		for _, d := range defs {
			changed, err := m.st.UpsertModuleRoleDef(sys, d)
			if err != nil {
				return res, err
			}
			if changed {
				upserted = append(upserted, d)
			}
		}
		if reg.DeclaresRoles {
			keep := map[string]bool{}
			for _, r := range reg.Roles {
				keep[r.Slug] = true // rejected roles keep their previous definition
			}
			current, err := m.st.ModuleRoleDefs(sys, reg.Module)
			if err != nil {
				return res, err
			}
			for _, d := range current {
				if !keep[d.Slug] && d.RetiredAt == nil {
					if err := m.st.RetireModuleRoleDef(sys, reg.Module, d.Slug); err != nil {
						return res, err
					}
					retired = append(retired, d)
					res.RolesRetired = append(res.RolesRetired, d.Slug)
				}
			}
		}
	}
	res.RolesUpserted = len(upserted)
	catalogueDefs, err := m.st.ModuleRoleDefs(sys, reg.Module)
	if err != nil {
		return res, err
	}
	// Tenants.
	skipped := map[string]*SkippedGrant{}
	kept := map[string]int{}
	for _, tid := range reg.Tenants {
		n, err := m.reg.Register(sys, tid, reg.Module, reg.Registrant, reg.Permissions)
		if err != nil {
			return res, err
		}
		res.Registered += n
		if err := m.migrate(sys, tid, reg.Module); err != nil {
			return res, err
		}
		if reg.Delegate != "" {
			continue
		}
		counts, err := m.syncRoles(sys, tid, reg.Module, catalogueDefs)
		if err != nil {
			return res, err
		}
		for slug, c := range counts {
			kept[slug] += c
		}
		for _, g := range reg.Grants {
			found, err := m.grantBuiltin(sys, tid, reg.Module, g)
			if err != nil {
				return res, err
			}
			if !found {
				sg := skipped[g.Role]
				if sg == nil {
					sg = &SkippedGrant{Role: g.Role, Reason: SkipRoleMissing}
					skipped[g.Role] = sg
				}
				sg.Tenants++
				if len(sg.Sample) < MaxSkippedSamples {
					sg.Sample = append(sg.Sample, tid)
				}
			}
		}
	}
	for _, g := range reg.Grants {
		if sg := skipped[g.Role]; sg != nil {
			res.Skipped = append(res.Skipped, *sg)
			delete(skipped, g.Role)
		}
	}
	// Audit (platform-wide events go to the platform tenant).
	at := m.PlatformTenant
	if at == "" && len(reg.Tenants) > 0 {
		at = reg.Tenants[0]
	}
	m.emit(audit.Event{Type: audit.ModuleRegistered, TenantID: at, ActorKind: "service", ActorService: reg.Registrant, Outcome: "ok", SubjectKind: "module", SubjectID: "",
		Details: map[string]any{"module": reg.Module, "delegate": reg.Delegate, "permissions": len(reg.Permissions), "roles": len(defs), "tenants": len(reg.Tenants),
			"role_errors": len(res.RoleErrors), "skipped_grants": len(res.Skipped)}})
	for _, d := range upserted {
		m.emit(audit.Event{Type: audit.ModuleRoleUpserted, TenantID: at, ActorKind: "service", ActorService: reg.Registrant, Outcome: "ok", SubjectKind: "module_role",
			Details: map[string]any{"module": d.Module, "slug": d.Slug, "permissions": qualify(d.Module, d.Permissions), "tenants": len(reg.Tenants)}})
	}
	for _, d := range retired {
		m.emit(audit.Event{Type: audit.ModuleRoleRetired, TenantID: at, ActorKind: "service", ActorService: reg.Registrant, Outcome: "ok", SubjectKind: "module_role",
			Details: map[string]any{"module": d.Module, "slug": d.Slug, "assignments_kept": kept[d.Slug]}})
	}
	return res, nil
}

func qualify(module string, shorts []string) []string {
	out := make([]string, 0, len(shorts))
	for _, s := range shorts {
		out = append(out, module+":"+s)
	}
	return out
}

// migrate runs the access-preserving migration of module in tenant once
// (D3): every role holding a legacy "res:act" the module registers is granted
// "module:res:act" too. The marker is set only after every tuple write
// succeeded, so a failure repeats the (idempotent) migration next time.
func (m *Modules) migrate(ctx context.Context, tenantID, module string) error {
	if err := m.st.EnsureTenantModule(ctx, tenantID, module); err != nil {
		return err
	}
	tm, err := m.st.TenantModule(ctx, tenantID, module)
	if err != nil {
		return err
	}
	if tm.LegacyMigratedAt != nil {
		return nil
	}
	catalogue, err := m.roles.st.ListPermissions(ctx, tenantID)
	if err != nil {
		return err
	}
	scoped := map[PermissionRef]bool{}
	for _, p := range catalogue {
		if p.Module == module {
			scoped[p.Ref()] = true
		}
	}
	roles, err := m.roles.st.ListRoles(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, ro := range roles {
		grants, err := m.roles.st.RolePermissions(ctx, tenantID, ro.ID)
		if err != nil {
			return err
		}
		var add []PermissionRef
		for _, g := range grants {
			if g.IsLegacy() && scoped[g.WithModule(module)] {
				add = append(add, g.WithModule(module))
			}
		}
		if len(add) == 0 {
			continue
		}
		n, err := m.roles.addGrants(ctx, tenantID, ro, add)
		if err != nil {
			return err
		}
		m.emit(audit.Event{Type: audit.PermissionMigrated, TenantID: tenantID, ActorKind: "system", Outcome: "ok", SubjectKind: "role", SubjectID: ro.ID,
			Details: map[string]any{"module": module, "role": ro.Slug, "count": n, "permissions": refsOf(add)}})
	}
	return m.st.MarkLegacyMigrated(ctx, tenantID, module)
}

// syncRoles makes the tenant's copies of module's roles match the catalogue
// definitions: missing ones are created (retired ones are not), fields,
// retirement and grants are updated. Assignments are never touched. It
// returns the direct assignments of every retired role (for the audit).
func (m *Modules) syncRoles(ctx context.Context, tenantID, module string, defs []store.ModuleRoleDef) (map[string]int, error) {
	roles, err := m.roles.st.ListRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	bySlug := map[string]store.Role{}
	for _, ro := range roles {
		if ro.OriginOf() == store.OriginModule && ro.Module == module {
			bySlug[ro.ModuleSlug] = ro
		}
	}
	catalogue, err := m.roles.st.ListPermissions(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	known := map[PermissionRef]bool{}
	for _, p := range catalogue {
		known[p.Ref()] = true
	}
	kept := map[string]int{}
	for _, d := range defs {
		var want []PermissionRef
		for _, s := range d.Permissions {
			if ref, err := permref.Qualify(module, s); err == nil && known[ref] {
				want = append(want, ref)
			}
		}
		ro, ok := bySlug[d.Slug]
		if !ok {
			if d.RetiredAt != nil {
				continue
			}
			slug, err := permref.ModuleRoleSlug(module, d.Slug)
			if err != nil {
				return nil, err
			}
			ro = store.Role{ID: store.NewID(), TenantID: tenantID, Slug: slug, DisplayName: d.DisplayName, Description: d.Description,
				Origin: store.OriginModule, Module: module, ModuleSlug: d.Slug}
			if err := m.authz.Write(ctx, tenantID, []Tuple{RoleTenantTuple(tenantID, slug)}, nil); err != nil {
				return nil, err
			}
			if err := m.roles.st.InsertRole(ctx, ro); err != nil {
				if !errors.Is(err, store.ErrConflict) {
					return nil, err
				}
				// A concurrent registration created it: continue with that row.
				if ro, err = m.moduleRole(ctx, tenantID, module, d.Slug); err != nil {
					return nil, err
				}
			}
		} else if ro.DisplayName != d.DisplayName || ro.Description != d.Description || (ro.RetiredAt == nil) != (d.RetiredAt == nil) {
			if err := m.roles.st.UpdateModuleRole(ctx, tenantID, ro.ID, d.DisplayName, d.Description, d.RetiredAt); err != nil {
				return nil, err
			}
		}
		if d.RetiredAt != nil {
			if ids, err := m.roles.st.RoleAssignees(ctx, tenantID, ro.ID); err == nil {
				kept[d.Slug] += len(ids)
			}
		}
		if _, _, err := m.roles.setGrants(ctx, tenantID, ro, want); err != nil {
			return nil, err
		}
	}
	return kept, nil
}

func (m *Modules) moduleRole(ctx context.Context, tenantID, module, slug string) (store.Role, error) {
	roles, err := m.roles.st.ListRoles(ctx, tenantID)
	if err != nil {
		return store.Role{}, err
	}
	for _, ro := range roles {
		if ro.OriginOf() == store.OriginModule && ro.Module == module && ro.ModuleSlug == slug {
			return ro, nil
		}
	}
	return store.Role{}, store.ErrNotFound
}

// grantBuiltin grants module-scoped refs to a built-in role; while the
// tenant still has legacy rows of the same "res:act" the legacy object is
// granted too (D2: an old gateway keeps working until prune-legacy).
func (m *Modules) grantBuiltin(ctx context.Context, tenantID, module string, g BuiltinGrant) (bool, error) {
	catalogue, err := m.roles.st.ListPermissions(ctx, tenantID)
	if err != nil {
		return false, err
	}
	legacy := map[PermissionRef]bool{}
	for _, p := range catalogue {
		if p.Module == "" {
			legacy[p.Ref()] = true
		}
	}
	var refs []PermissionRef
	for _, s := range g.Permissions {
		ref, err := permref.Qualify(module, s)
		if err != nil {
			return false, ErrBadRegistration
		}
		refs = append(refs, ref)
		if l := (PermissionRef{Resource: ref.Resource, Action: ref.Action}); legacy[l] {
			refs = append(refs, l)
		}
	}
	return m.roles.GrantBuiltin(ctx, tenantID, g.Role, refs)
}

// InstantiateTenant gives a new tenant every non-retired module permission
// and module role of the catalogue, so it does not wait for the modules'
// next registration. Built-in grants still arrive with that registration.
func (m *Modules) InstantiateTenant(ctx context.Context, tenantID string) error {
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	mods, err := m.st.Modules(sys)
	if err != nil {
		return err
	}
	for _, mod := range mods {
		if mod.RetiredAt != nil {
			continue
		}
		perms, err := m.st.ModulePermissions(sys, mod.Name)
		if err != nil {
			return err
		}
		var defs []Permission
		for _, p := range perms {
			if p.RetiredAt == nil {
				defs = append(defs, Permission{Resource: p.Resource, Action: p.Action, Description: p.Description})
			}
		}
		if _, err := m.reg.Register(sys, tenantID, mod.Name, "auth", defs); err != nil {
			return err
		}
		if err := m.migrate(sys, tenantID, mod.Name); err != nil {
			return err
		}
		roleDefs, err := m.st.ModuleRoleDefs(sys, mod.Name)
		if err != nil {
			return err
		}
		if _, err := m.syncRoles(sys, tenantID, mod.Name, roleDefs); err != nil {
			return err
		}
	}
	return nil
}

// ErrUnknownModule is returned for a module the catalogue does not know.
var ErrUnknownModule = errors.New("authz: unknown module")

// RetireModule marks a module removed from the platform (operator CLI): its
// role copies are retired in every tenant (grants and assignments kept) and
// its permissions disappear from the role editor. It returns the retired
// role slugs.
func (m *Modules) RetireModule(ctx context.Context, name string) ([]string, error) {
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	before, err := m.st.ModuleRoleDefs(sys, name)
	if err != nil {
		return nil, err
	}
	if err := m.st.RetireModule(sys, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrUnknownModule
		}
		return nil, err
	}
	defs, err := m.st.ModuleRoleDefs(sys, name)
	if err != nil {
		return nil, err
	}
	var tenants []string
	if m.Tenants != nil {
		if tenants, err = m.Tenants(sys); err != nil {
			return nil, err
		}
	}
	kept := map[string]int{}
	for _, tid := range tenants {
		counts, err := m.syncRoles(sys, tid, name, defs)
		if err != nil {
			return nil, err
		}
		for slug, c := range counts {
			kept[slug] += c
		}
	}
	at := m.PlatformTenant
	if at == "" && len(tenants) > 0 {
		at = tenants[0]
	}
	var slugs []string
	for _, d := range before {
		if d.RetiredAt != nil {
			continue
		}
		slugs = append(slugs, d.Slug)
		m.emit(audit.Event{Type: audit.ModuleRoleRetired, TenantID: at, ActorKind: "operator", Outcome: "ok", Reason: "module_retired", SubjectKind: "module_role",
			Details: map[string]any{"module": name, "slug": d.Slug, "assignments_kept": kept[d.Slug]}})
	}
	return slugs, nil
}

func (m *Modules) emit(e audit.Event) {
	if m.audit != nil && e.TenantID != "" {
		_ = m.audit.Emit(e)
	}
}
