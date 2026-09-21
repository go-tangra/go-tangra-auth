package authz

import (
	"context"
	"errors"
	"strings"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// Role refusals.
var (
	ErrBuiltin = errors.New("builtin")
	ErrRoleRef = errors.New("validation_failed")
)

// RoleCRUDStore persists roles, their permission mirrors and assignments.
type RoleCRUDStore interface {
	RoleStore
	InsertRole(ctx context.Context, r store.Role) error
	Role(ctx context.Context, tenantID, id string) (store.Role, error)
	ListRoles(ctx context.Context, tenantID string) ([]store.Role, error)
	UpdateRoleName(ctx context.Context, tenantID, id, name string) error
	RemoveRole(ctx context.Context, tenantID, id string) error
	ReplaceRolePermissions(ctx context.Context, tenantID, roleID string, perms [][2]string) error
	RoleAssignees(ctx context.Context, tenantID, roleID string) ([]string, error)
	ListPermissions(ctx context.Context, tenantID string) ([][3]string, error)
}

// RoleView is a role with its permissions.
type RoleView struct {
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	DisplayName string   `json:"display_name"`
	Builtin     bool     `json:"builtin"`
	Permissions []string `json:"permissions"`
}

// RoleName is the member-visible part of a role.
type RoleName struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// Names lists slug and display name of every role of the tenant; readable by
// any member (no permissions are disclosed).
func (r *Roles) Names(ctx context.Context, tenantID string) ([]RoleName, error) {
	roles, err := r.st.ListRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]RoleName, 0, len(roles))
	for _, ro := range roles {
		out = append(out, RoleName{Slug: ro.Slug, DisplayName: ro.DisplayName})
	}
	return out, nil
}

// Roles manages custom roles. Built-in roles (owner, admin, member) are
// immutable: they are defined by the model, not by permission sets.
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

// List returns every role of the actor's tenant with its permissions.
func (r *Roles) List(ctx context.Context, tenantID string) ([]RoleView, error) {
	if err := r.authz.guard.Require(ctx, tenantID); err != nil {
		return nil, err
	}
	roles, err := r.st.ListRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]RoleView, 0, len(roles))
	for _, ro := range roles {
		perms, err := r.st.RolePermissions(ctx, tenantID, ro.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, RoleView{ID: ro.ID, Slug: ro.Slug, DisplayName: ro.DisplayName, Builtin: ro.Builtin, Permissions: refsOf(perms)})
	}
	return out, nil
}

func refsOf(perms [][2]string) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, p[0]+":"+p[1])
	}
	return out
}

// parsePerms validates permission refs against the tenant catalogue.
func (r *Roles) parsePerms(ctx context.Context, tenantID string, refs []string) ([]PermissionRef, error) {
	catalogue, err := r.st.ListPermissions(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, p := range catalogue {
		known[p[0]+":"+p[1]] = true
	}
	seen := map[string]bool{}
	out := make([]PermissionRef, 0, len(refs))
	for _, s := range refs {
		ref, err := ParsePermissionRef(s)
		if err != nil || !known[s] {
			return nil, ErrRoleRef
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, ref)
		}
	}
	return out, nil
}

// Create adds a custom role granting the given permissions. The actor must
// hold every permission (self-escalation guard).
func (r *Roles) Create(ctx context.Context, tenantID, slug, displayName string, permRefs []string) (RoleView, error) {
	actor, ok := tenantctx.FromContext(ctx)
	if !ok {
		return RoleView{}, tenantctx.ErrNoActor
	}
	if err := r.authz.guard.Require(ctx, tenantID); err != nil {
		return RoleView{}, err
	}
	if _, err := ParseSlug(slug); err != nil || slug == "owner" || slug == "admin" || slug == "member" || strings.TrimSpace(displayName) == "" || len(displayName) > 120 {
		return RoleView{}, ErrRoleRef
	}
	perms, err := r.parsePerms(ctx, tenantID, permRefs)
	if err != nil {
		return RoleView{}, err
	}
	if err := r.guard.MayGrant(ctx, actor, tenantID, perms); err != nil {
		return RoleView{}, err
	}
	ro := store.Role{ID: store.NewID(), TenantID: tenantID, Slug: slug, DisplayName: strings.TrimSpace(displayName)}
	if err := r.st.InsertRole(ctx, ro); err != nil {
		return RoleView{}, err
	}
	if err := r.st.ReplaceRolePermissions(ctx, tenantID, ro.ID, pairs(perms)); err != nil {
		return RoleView{}, err
	}
	tuples := []Tuple{RoleTenantTuple(tenantID, slug)}
	for _, p := range perms {
		tuples = append(tuples, GrantTuple(tenantID, slug, p))
	}
	if err := r.authz.Write(ctx, tenantID, tuples, nil); err != nil {
		return RoleView{}, err
	}
	r.emit(audit.Event{Type: audit.RoleCreated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "role", SubjectID: ro.ID, Details: map[string]any{"slug": slug, "permissions": permRefs}})
	return RoleView{ID: ro.ID, Slug: slug, DisplayName: ro.DisplayName, Permissions: refsOf(pairs(perms))}, nil
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
	if ro.Builtin {
		return RoleView{}, ErrBuiltin
	}
	perms, err := r.parsePerms(ctx, tenantID, permRefs)
	if err != nil {
		return RoleView{}, err
	}
	current, err := r.st.RolePermissions(ctx, tenantID, id)
	if err != nil {
		return RoleView{}, err
	}
	var adds, removes []Tuple
	var granting []PermissionRef
	have := map[string]bool{}
	for _, p := range current {
		have[p[0]+":"+p[1]] = true
	}
	want := map[string]bool{}
	for _, p := range perms {
		want[p.String()] = true
		if !have[p.String()] {
			adds = append(adds, GrantTuple(tenantID, ro.Slug, p))
			granting = append(granting, p)
		}
	}
	for _, p := range current {
		if !want[p[0]+":"+p[1]] {
			removes = append(removes, GrantTuple(tenantID, ro.Slug, PermissionRef{Resource: p[0], Action: p[1]}))
		}
	}
	if err := r.guard.MayGrant(ctx, actor, tenantID, granting); err != nil {
		return RoleView{}, err
	}
	if strings.TrimSpace(displayName) != "" && displayName != ro.DisplayName {
		if len(displayName) > 120 {
			return RoleView{}, ErrRoleRef
		}
		if err := r.st.UpdateRoleName(ctx, tenantID, id, strings.TrimSpace(displayName)); err != nil {
			return RoleView{}, err
		}
		ro.DisplayName = strings.TrimSpace(displayName)
	}
	if err := r.st.ReplaceRolePermissions(ctx, tenantID, id, pairs(perms)); err != nil {
		return RoleView{}, err
	}
	if err := r.authz.Write(ctx, tenantID, adds, removes); err != nil {
		return RoleView{}, err
	}
	r.emit(audit.Event{Type: audit.RoleUpdated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "role", SubjectID: id, Details: map[string]any{"permissions": permRefs}})
	return RoleView{ID: id, Slug: ro.Slug, DisplayName: ro.DisplayName, Permissions: refsOf(pairs(perms))}, nil
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
	if ro.Builtin {
		return ErrBuiltin
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
		removes = append(removes, GrantTuple(tenantID, ro.Slug, PermissionRef{Resource: p[0], Action: p[1]}))
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

func pairs(perms []PermissionRef) [][2]string {
	out := make([][2]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, [2]string{p.Resource, p.Action})
	}
	return out
}

func (r *Roles) emit(e audit.Event) {
	if r.audit != nil {
		_ = r.audit.Emit(e)
	}
}

// GrantBuiltin grants permissions to a builtin role without an actor
// (service start-up and tenant creation). Missing grants are added; existing
// ones are kept, so the call is idempotent.
func (r *Roles) GrantBuiltin(ctx context.Context, tenantID, slug string, refs []string) error {
	roles, err := r.st.ListRoles(ctx, tenantID)
	if err != nil {
		return err
	}
	var role *store.Role
	for i := range roles {
		if roles[i].Slug == slug {
			role = &roles[i]
		}
	}
	if role == nil {
		return nil // the tenant does not have this builtin role
	}
	current, err := r.st.RolePermissions(ctx, tenantID, role.ID)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, p := range current {
		have[p[0]+":"+p[1]] = true
	}
	var tuples []Tuple
	union := append([][2]string(nil), current...)
	for _, s := range refs {
		if have[s] {
			continue
		}
		ref, err := ParsePermissionRef(s)
		if err != nil {
			return ErrRoleRef
		}
		have[s] = true
		union = append(union, [2]string{ref.Resource, ref.Action})
		tuples = append(tuples, GrantTuple(tenantID, slug, ref))
	}
	if len(tuples) == 0 {
		return nil
	}
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	if err := r.authz.Write(sys, tenantID, tuples, nil); err != nil {
		return err
	}
	if err := r.st.ReplaceRolePermissions(ctx, tenantID, role.ID, union); err != nil {
		return err
	}
	r.emit(audit.Event{Type: audit.RoleUpdated, TenantID: tenantID, ActorKind: "system", Outcome: "ok", SubjectKind: "role", SubjectID: role.ID, Details: map[string]any{"slug": slug, "granted": len(tuples)}})
	return nil
}
