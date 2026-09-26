package authz

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/permref"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Role refusals.
var (
	ErrBuiltin = errors.New("builtin")
	ErrRoleRef = errors.New("validation_failed")
	// ErrManagedRole refuses changes to a module role (feature 019): it is
	// defined by its module; administrators clone it instead.
	ErrManagedRole = errors.New("managed_role")
	// ErrRoleRetired refuses a new assignment of a role its module no
	// longer provides (existing assignments are kept).
	ErrRoleRetired = errors.New("role_retired")
	// ErrRoleConflict is returned when the slug is taken.
	ErrRoleConflict = errors.New("conflict")
)

// RoleCRUDStore persists roles, their permission mirrors and assignments.
type RoleCRUDStore interface {
	RoleStore
	InsertRole(ctx context.Context, r store.Role) error
	Role(ctx context.Context, tenantID, id string) (store.Role, error)
	ListRoles(ctx context.Context, tenantID string) ([]store.Role, error)
	UpdateRoleName(ctx context.Context, tenantID, id, name string) error
	RemoveRole(ctx context.Context, tenantID, id string) error
	ReplaceRolePermissions(ctx context.Context, tenantID, roleID string, perms []PermissionRef) error
	RoleAssignees(ctx context.Context, tenantID, roleID string) ([]string, error)
	ListPermissions(ctx context.Context, tenantID string) ([]store.Permission, error)
	// Feature 019.
	Modules(ctx context.Context) ([]store.Module, error)
	AdoptBuiltinRole(ctx context.Context, tenantID, id string) error
	UpdateModuleRole(ctx context.Context, tenantID, id, name, description string, retiredAt *time.Time) error
}

// RoleView is a role with its permissions (qualified refs; legacy grants
// keep the "resource:action" form until prune-legacy).
type RoleView struct {
	ID                string     `json:"id"`
	Slug              string     `json:"slug"`
	DisplayName       string     `json:"display_name"`
	Description       string     `json:"description"`
	Builtin           bool       `json:"builtin"`
	Origin            string     `json:"origin"`
	Module            string     `json:"module"`
	ModuleDisplayName string     `json:"module_display_name"`
	ModuleSlug        string     `json:"module_slug"`
	Locked            bool       `json:"locked"`
	Retired           bool       `json:"retired"`
	RetiredAt         *time.Time `json:"retired_at"`
	Permissions       []string   `json:"permissions"`
}

// RoleName is the member-visible part of a role.
type RoleName struct {
	Slug              string `json:"slug"`
	DisplayName       string `json:"display_name"`
	Origin            string `json:"origin"`
	ModuleDisplayName string `json:"module_display_name"`
	Retired           bool   `json:"retired"`
}

// Roles manages custom roles. Built-in roles (owner, admin, member, auditor,
// operator) are immutable, module roles are managed by their module.
type Roles struct {
	st    RoleCRUDStore
	authz *Client
	guard *Escalation
	audit *audit.Writer
}

// NewRoles wires the service.
func NewRoles(st RoleCRUDStore, c *Client, g *Escalation, a *audit.Writer) *Roles {
	return &Roles{st: st, authz: c, guard: g, audit: a}
}

func (r *Roles) moduleNames(ctx context.Context) map[string]string {
	mods, err := r.st.Modules(ctx)
	if err != nil {
		mods = nil
	}
	names, _ := ModuleDisplayNames(mods)
	return names
}

func view(ro store.Role, names map[string]string, perms []PermissionRef) RoleView {
	v := RoleView{ID: ro.ID, Slug: ro.Slug, DisplayName: ro.DisplayName, Description: ro.Description, Builtin: ro.Builtin, Origin: ro.OriginOf(),
		Module: ro.Module, ModuleSlug: ro.ModuleSlug, RetiredAt: ro.RetiredAt, Retired: ro.RetiredAt != nil, Permissions: refsOf(perms)}
	v.Locked = v.Origin != store.OriginCustom
	if ro.Module != "" {
		v.ModuleDisplayName = DisplayName(names, ro.Module)
	}
	return v
}

// Names lists every role of the tenant with its origin; readable by any
// member (no permissions are disclosed).
func (r *Roles) Names(ctx context.Context, tenantID string) ([]RoleName, error) {
	roles, err := r.st.ListRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	names := r.moduleNames(ctx)
	out := make([]RoleName, 0, len(roles))
	for _, ro := range roles {
		n := RoleName{Slug: ro.Slug, DisplayName: ro.DisplayName, Origin: ro.OriginOf(), Retired: ro.RetiredAt != nil}
		if ro.Module != "" {
			n.ModuleDisplayName = DisplayName(names, ro.Module)
		}
		out = append(out, n)
	}
	return out, nil
}

// List returns every role of the actor's tenant with its permissions.
func (r *Roles) List(ctx context.Context, tenantID string) ([]RoleView, error) {
	if err := r.authz.guard.Require(ctx, tenantID); err != nil {
		return nil, err
	}
	roles, err := r.st.ListRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	names := r.moduleNames(ctx)
	out := make([]RoleView, 0, len(roles))
	for _, ro := range roles {
		perms, err := r.st.RolePermissions(ctx, tenantID, ro.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, view(ro, names, perms))
	}
	return out, nil
}

func refsOf(perms []PermissionRef) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, p.String())
	}
	return out
}

// parsePerms validates permission refs against the tenant catalogue. Legacy
// refs are accepted only when kept holds them (a role update keeping a grant
// made before module-scoped permissions); nothing new is granted legacy.
func (r *Roles) parsePerms(ctx context.Context, tenantID string, refs []string, kept map[PermissionRef]bool) ([]PermissionRef, error) {
	catalogue, err := r.st.ListPermissions(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	known := map[PermissionRef]bool{}
	for _, p := range catalogue {
		known[p.Ref()] = true
	}
	seen := map[PermissionRef]bool{}
	out := make([]PermissionRef, 0, len(refs))
	for _, s := range refs {
		ref, err := ParsePermissionRef(s)
		if err != nil || !known[ref] || (ref.IsLegacy() && !kept[ref]) {
			return nil, ErrRoleRef
		}
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	return out, nil
}

func validDisplayName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 120 {
		return "", false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return "", false
		}
	}
	return s, true
}

// Create adds a custom role granting the given permissions. The actor must
// hold every permission (self-escalation guard). Built-in slugs and slugs
// with a dot (the module role space) are refused.
func (r *Roles) Create(ctx context.Context, tenantID, slug, displayName string, permRefs []string) (RoleView, error) {
	return r.create(ctx, tenantID, slug, displayName, permRefs, nil)
}

func (r *Roles) create(ctx context.Context, tenantID, slug, displayName string, permRefs []string, cloned *store.Role) (RoleView, error) {
	actor, ok := tenantctx.FromContext(ctx)
	if !ok {
		return RoleView{}, tenantctx.ErrNoActor
	}
	if err := r.authz.guard.Require(ctx, tenantID); err != nil {
		return RoleView{}, err
	}
	name, ok := validDisplayName(displayName)
	if _, err := permref.ParseCustomSlug(slug); err != nil || !ok {
		return RoleView{}, ErrRoleRef
	}
	perms, err := r.parsePerms(ctx, tenantID, permRefs, nil)
	if err != nil {
		return RoleView{}, err
	}
	if err := r.guard.MayGrant(ctx, actor, tenantID, perms); err != nil {
		return RoleView{}, err
	}
	ro := store.Role{ID: store.NewID(), TenantID: tenantID, Slug: slug, DisplayName: name, Origin: store.OriginCustom}
	if err := r.st.InsertRole(ctx, ro); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return RoleView{}, ErrRoleConflict
		}
		return RoleView{}, err
	}
	tuples := []Tuple{RoleTenantTuple(tenantID, slug)}
	for _, p := range perms {
		tuples = append(tuples, GrantTuple(tenantID, slug, p))
	}
	if err := r.authz.Write(ctx, tenantID, tuples, nil); err != nil {
		return RoleView{}, err
	}
	if err := r.st.ReplaceRolePermissions(ctx, tenantID, ro.ID, perms); err != nil {
		return RoleView{}, err
	}
	refs := refsOf(perms)
	if cloned != nil {
		r.emit(audit.Event{Type: audit.RoleCloned, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "role", SubjectID: ro.ID,
			Details: map[string]any{"source": cloned.ID, "source_slug": cloned.Slug, "slug": slug, "permissions": refs}})
	} else {
		r.emit(audit.Event{Type: audit.RoleCreated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "role", SubjectID: ro.ID, Details: map[string]any{"slug": slug, "permissions": refs}})
	}
	return view(ro, nil, perms), nil
}

// Clone creates a custom role with the current permissions of role id (any
// role but owner), through the same checks as Create: the actor must hold
// every permission. Legacy grants of the source are not copied.
func (r *Roles) Clone(ctx context.Context, tenantID, id, slug, displayName string) (RoleView, error) {
	if err := r.authz.guard.Require(ctx, tenantID); err != nil {
		return RoleView{}, err
	}
	src, err := r.st.Role(ctx, tenantID, id)
	if err != nil {
		return RoleView{}, err
	}
	if src.Slug == "owner" {
		return RoleView{}, ErrBuiltin
	}
	perms, err := r.st.RolePermissions(ctx, tenantID, id)
	if err != nil {
		return RoleView{}, err
	}
	var refs []string
	for _, p := range perms {
		if !p.IsLegacy() {
			refs = append(refs, p.String())
		}
	}
	return r.create(ctx, tenantID, slug, displayName, refs, &src)
}

// locked refuses changes to built-in and module roles.
func locked(ro store.Role) error {
	switch ro.OriginOf() {
	case store.OriginBuiltin:
		return ErrBuiltin
	case store.OriginModule:
		return ErrManagedRole
	}
	return nil
}

// Update replaces a custom role's name and permissions.
func (r *Roles) Update(ctx context.Context, tenantID, id, displayName string, permRefs []string) (RoleView, error) {
	actor, ok := tenantctx.FromContext(ctx)
	if !ok {
		return RoleView{}, tenantctx.ErrNoActor
	}
	if err := r.authz.guard.Require(ctx, tenantID); err != nil {
		return RoleView{}, err
	}
	ro, err := r.st.Role(ctx, tenantID, id)
	if err != nil {
		return RoleView{}, err
	}
	if err := locked(ro); err != nil {
		return RoleView{}, err
	}
	current, err := r.st.RolePermissions(ctx, tenantID, id)
	if err != nil {
		return RoleView{}, err
	}
	have := map[PermissionRef]bool{}
	for _, p := range current {
		have[p] = true
	}
	perms, err := r.parsePerms(ctx, tenantID, permRefs, have)
	if err != nil {
		return RoleView{}, err
	}
	var adds, removes []Tuple
	var granting []PermissionRef
	want := map[PermissionRef]bool{}
	for _, p := range perms {
		want[p] = true
		if !have[p] {
			adds = append(adds, GrantTuple(tenantID, ro.Slug, p))
			granting = append(granting, p)
		}
	}
	for _, p := range current {
		if !want[p] {
			removes = append(removes, GrantTuple(tenantID, ro.Slug, p))
		}
	}
	if err := r.guard.MayGrant(ctx, actor, tenantID, granting); err != nil {
		return RoleView{}, err
	}
	if strings.TrimSpace(displayName) != "" && strings.TrimSpace(displayName) != ro.DisplayName {
		name, ok := validDisplayName(displayName)
		if !ok {
			return RoleView{}, ErrRoleRef
		}
		if err := r.st.UpdateRoleName(ctx, tenantID, id, name); err != nil {
			return RoleView{}, err
		}
		ro.DisplayName = name
	}
	if err := r.authz.Write(ctx, tenantID, adds, removes); err != nil {
		return RoleView{}, err
	}
	if err := r.st.ReplaceRolePermissions(ctx, tenantID, id, perms); err != nil {
		return RoleView{}, err
	}
	r.emit(audit.Event{Type: audit.RoleUpdated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "role", SubjectID: id, Details: map[string]any{"permissions": refsOf(perms)}})
	return view(ro, nil, perms), nil
}

// Remove deletes a custom role, unassigning everyone who held it.
func (r *Roles) Remove(ctx context.Context, tenantID, id string) error {
	actor, ok := tenantctx.FromContext(ctx)
	if !ok {
		return tenantctx.ErrNoActor
	}
	if err := r.authz.guard.Require(ctx, tenantID); err != nil {
		return err
	}
	ro, err := r.st.Role(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := locked(ro); err != nil {
		return err
	}
	assignees, err := r.st.RoleAssignees(ctx, tenantID, id)
	if err != nil {
		return err
	}
	perms, err := r.st.RolePermissions(ctx, tenantID, id)
	if err != nil {
		return err
	}
	var removes []Tuple
	for _, uid := range assignees {
		removes = append(removes, RoleAssignmentTuple(tenantID, ro.Slug, uid))
	}
	for _, p := range perms {
		removes = append(removes, GrantTuple(tenantID, ro.Slug, p))
	}
	removes = append(removes, RoleTenantTuple(tenantID, ro.Slug))
	if err := r.st.RemoveRole(ctx, tenantID, id); err != nil {
		return err
	}
	if err := r.authz.Write(ctx, tenantID, nil, removes); err != nil {
		return err
	}
	r.emit(audit.Event{Type: audit.RoleDeleted, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "role", SubjectID: id, Details: map[string]any{"slug": ro.Slug, "unassigned": len(assignees)}})
	return nil
}

func (r *Roles) emit(e audit.Event) {
	if r.audit != nil {
		_ = r.audit.Emit(e)
	}
}

// setGrants makes the role grant exactly want: the difference to the mirror
// is written to OpenFGA first (idempotent writes), then the mirror is
// replaced, so a failure between the two is repaired by the next call. It
// reports how many grants were added and removed.
func (r *Roles) setGrants(ctx context.Context, tenantID string, ro store.Role, want []PermissionRef) (int, int, error) {
	current, err := r.st.RolePermissions(ctx, tenantID, ro.ID)
	if err != nil {
		return 0, 0, err
	}
	have := map[PermissionRef]bool{}
	for _, p := range current {
		have[p] = true
	}
	wanted := map[PermissionRef]bool{}
	list := make([]PermissionRef, 0, len(want))
	var adds, removes []Tuple
	for _, p := range want {
		if wanted[p] {
			continue
		}
		wanted[p] = true
		list = append(list, p)
		if !have[p] {
			adds = append(adds, GrantTuple(tenantID, ro.Slug, p))
		}
	}
	for _, p := range current {
		if !wanted[p] {
			removes = append(removes, GrantTuple(tenantID, ro.Slug, p))
		}
	}
	if len(adds) == 0 && len(removes) == 0 {
		return 0, 0, nil
	}
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	if err := r.authz.Write(sys, tenantID, adds, removes); err != nil {
		return 0, 0, err
	}
	if err := r.st.ReplaceRolePermissions(ctx, tenantID, ro.ID, list); err != nil {
		return 0, 0, err
	}
	return len(adds), len(removes), nil
}

// addGrants adds perms to the role's grants (keeping the others).
func (r *Roles) addGrants(ctx context.Context, tenantID string, ro store.Role, perms []PermissionRef) (int, error) {
	current, err := r.st.RolePermissions(ctx, tenantID, ro.ID)
	if err != nil {
		return 0, err
	}
	added, _, err := r.setGrants(ctx, tenantID, ro, append(append([]PermissionRef(nil), current...), perms...))
	return added, err
}

// GrantBuiltin grants permissions to a built-in role without an actor
// (service start-up, registrations). Only roles with origin builtin are
// targeted: a custom role that happens to share the slug (e.g. a customer
// "operator") receives nothing. It reports false when the tenant has no such
// built-in role. Missing grants are added; existing ones are kept.
func (r *Roles) GrantBuiltin(ctx context.Context, tenantID, slug string, refs []PermissionRef) (bool, error) {
	roles, err := r.st.ListRoles(ctx, tenantID)
	if err != nil {
		return false, err
	}
	var role *store.Role
	for i := range roles {
		if roles[i].Slug == slug && roles[i].OriginOf() == store.OriginBuiltin {
			role = &roles[i]
		}
	}
	if role == nil {
		return false, nil
	}
	added, err := r.addGrants(ctx, tenantID, *role, refs)
	if err != nil {
		return true, err
	}
	if added > 0 {
		r.emit(audit.Event{Type: audit.RoleUpdated, TenantID: tenantID, ActorKind: "system", Outcome: "ok", SubjectKind: "role", SubjectID: role.ID, Details: map[string]any{"slug": slug, "granted": added}})
	}
	return true, nil
}

// EnsureBuiltin makes sure the tenant has the built-in roles slugs (feature
// 019: auditor in every tenant). A custom role already using a slug is adopted
// as the built-in role, keeping its grants and assignments. It returns the
// slugs it created or adopted.
func (r *Roles) EnsureBuiltin(ctx context.Context, tenantID string, slugs []string) ([]string, error) {
	roles, err := r.st.ListRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	bySlug := map[string]store.Role{}
	for _, ro := range roles {
		bySlug[ro.Slug] = ro
	}
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	var changed []string
	for _, slug := range slugs {
		ro, ok := bySlug[slug]
		switch {
		case ok && ro.OriginOf() != store.OriginCustom:
			continue
		case ok:
			if err := r.st.AdoptBuiltinRole(ctx, tenantID, ro.ID); err != nil {
				return changed, err
			}
			r.emit(audit.Event{Type: audit.RoleUpdated, TenantID: tenantID, ActorKind: "system", Outcome: "ok", SubjectKind: "role", SubjectID: ro.ID, Details: map[string]any{"slug": slug, "adopted": true}})
		default:
			ro = store.Role{ID: store.NewID(), TenantID: tenantID, Slug: slug, DisplayName: strings.ToUpper(slug[:1]) + slug[1:], Builtin: true, Origin: store.OriginBuiltin}
			if err := r.authz.Write(sys, tenantID, []Tuple{RoleTenantTuple(tenantID, slug)}, nil); err != nil {
				return changed, err
			}
			if err := r.st.InsertRole(ctx, ro); err != nil {
				return changed, err
			}
			r.emit(audit.Event{Type: audit.RoleCreated, TenantID: tenantID, ActorKind: "system", Outcome: "ok", SubjectKind: "role", SubjectID: ro.ID, Details: map[string]any{"slug": slug, "builtin": true}})
		}
		changed = append(changed, slug)
	}
	return changed, nil
}
