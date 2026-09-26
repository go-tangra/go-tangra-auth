package authz

import (
	"context"
	"errors"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Assignment refusals.
var (
	ErrSelfEscalation = errors.New("self_escalation")
	ErrLastOwner      = errors.New("last_owner")
)

// RoleStore is the role/binding persistence used for assignment.
type RoleStore interface {
	RolesByID(ctx context.Context, tenantID string, ids []string) ([]store.Role, error)
	UserRoles(ctx context.Context, tenantID, userID string) ([]store.Role, error)
	RolePermissions(ctx context.Context, tenantID, roleID string) ([]PermissionRef, error)
	ReplaceBindings(ctx context.Context, tenantID, userID, grantedBy string, roleIDs []string) error
	CountWithRole(ctx context.Context, tenantID, slug string) (int, error)
}

// Assigner replaces a user's roles: mirror rows in the database, assignee
// tuples in OpenFGA, decision-cache invalidation and an audit event.
type Assigner struct {
	st    RoleStore
	authz *Client
	audit *audit.Writer
}

// NewAssigner wires the assigner.
func NewAssigner(st RoleStore, c *Client, a *audit.Writer) *Assigner {
	return &Assigner{st: st, authz: c, audit: a}
}

// AssignRoles sets the target's roles to roleIDs. The actor (from ctx) must
// hold every permission the new roles grant unless they are an owner; the
// last owner cannot lose the owner role.
func (a *Assigner) AssignRoles(ctx context.Context, tenantID, userID string, roleIDs []string) ([]string, error) {
	actor, ok := tenantctx.FromContext(ctx)
	if !ok {
		return nil, tenantctx.ErrNoActor
	}
	if err := a.authz.guard.Require(ctx, tenantID); err != nil {
		return nil, err
	}
	want, err := a.st.RolesByID(ctx, tenantID, dedupe(roleIDs))
	if err != nil {
		return nil, err
	}
	have, err := a.st.UserRoles(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	var adding []string
	for _, r := range want {
		if !containsRole(have, r.ID) {
			adding = append(adding, r.ID)
		}
	}
	if err := a.MayAssign(ctx, actor, tenantID, adding); err != nil {
		if errors.Is(err, ErrSelfEscalation) || errors.Is(err, ErrRoleRetired) {
			return nil, a.refuse(actor, tenantID, userID, err)
		}
		return nil, err
	}
	if containsSlug(have, "owner") && !containsSlug(want, "owner") {
		n, err := a.st.CountWithRole(ctx, tenantID, "owner")
		if err != nil {
			return nil, err
		}
		if n <= 1 {
			return nil, a.refuse(actor, tenantID, userID, ErrLastOwner)
		}
	}
	ids := make([]string, 0, len(want))
	slugs := make([]string, 0, len(want))
	var adds, removes []Tuple
	for _, r := range want {
		ids = append(ids, r.ID)
		slugs = append(slugs, r.Slug)
		if !containsRole(have, r.ID) {
			adds = append(adds, RoleAssignmentTuple(tenantID, r.Slug, userID))
			if r.Slug == "owner" {
				adds = append(adds, MembershipTuple(tenantID, userID, "owner"))
			}
		}
	}
	for _, r := range have {
		if !containsRole(want, r.ID) {
			removes = append(removes, RoleAssignmentTuple(tenantID, r.Slug, userID))
			if r.Slug == "owner" {
				removes = append(removes, MembershipTuple(tenantID, userID, "owner"))
			}
		}
	}
	if err := a.st.ReplaceBindings(ctx, tenantID, userID, actor.UserID, ids); err != nil {
		return nil, err
	}
	if err := a.authz.Write(ctx, tenantID, adds, removes); err != nil {
		return nil, err
	}
	for _, t := range adds {
		if t.Relation == "assignee" {
			a.emit(audit.Event{Type: audit.RoleAssigned, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "user", SubjectID: userID, Details: map[string]any{"role": t.Object}})
		}
	}
	for _, t := range removes {
		if t.Relation == "assignee" {
			a.emit(audit.Event{Type: audit.RoleRevoked, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "user", SubjectID: userID, Details: map[string]any{"role": t.Object}})
		}
	}
	return slugs, nil
}

// refuseRetired returns ErrRoleRetired when any role is retired (feature
// 019): a module no longer provides it, so it may only be kept, not newly
// assigned — whoever the actor is.
func refuseRetired(roles []store.Role) error {
	for _, r := range roles {
		if r.RetiredAt != nil {
			return ErrRoleRetired
		}
	}
	return nil
}

// MayAssign reports whether actor may grant roleIDs in tenantID. It is a
// pure check shared by AssignRoles and invitations: every role counts as new,
// nothing is written. Retired roles are refused (ErrRoleRetired). Owners may
// grant anything else; everyone else is refused
// owner/admin and any role carrying a permission they do not hold
// (ErrSelfEscalation). Unknown role ids fail with store.ErrNotFound.
func (a *Assigner) MayAssign(ctx context.Context, actor tenantctx.Actor, tenantID string, roleIDs []string) error {
	if err := a.authz.guard.Require(ctx, tenantID); err != nil {
		return err
	}
	if len(roleIDs) == 0 {
		return nil
	}
	roles, err := a.st.RolesByID(ctx, tenantID, dedupe(roleIDs))
	if err != nil {
		return err
	}
	if err := refuseRetired(roles); err != nil {
		return err
	}
	if hasSlug(actor.Roles, "owner") {
		return nil
	}
	var granting []PermissionRef
	for _, r := range roles {
		if r.Slug == "owner" || r.Slug == "admin" {
			return ErrSelfEscalation
		}
		perms, err := a.st.RolePermissions(ctx, tenantID, r.ID)
		if err != nil {
			return err
		}
		granting = append(granting, perms...)
	}
	return NewEscalation(a.authz).MayGrant(ctx, actor, tenantID, granting)
}

func (a *Assigner) refuse(actor tenantctx.Actor, tenantID, userID string, err error) error {
	a.emit(audit.Event{Type: audit.RoleAssigned, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: err.Error(), SubjectKind: "user", SubjectID: userID})
	return err
}

func (a *Assigner) emit(e audit.Event) {
	if a.audit != nil {
		_ = a.audit.Emit(e)
	}
}

func dedupe(ids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func hasSlug(slugs []string, s string) bool {
	for _, x := range slugs {
		if x == s {
			return true
		}
	}
	return false
}

func containsRole(roles []store.Role, id string) bool {
	for _, r := range roles {
		if r.ID == id {
			return true
		}
	}
	return false
}

func containsSlug(roles []store.Role, slug string) bool {
	for _, r := range roles {
		if r.Slug == slug {
			return true
		}
	}
	return false
}
