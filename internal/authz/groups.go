package authz

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Group refusals (feature 004).
var (
	ErrForbidden           = errors.New("forbidden")
	ErrInvalidName         = errors.New("invalid_name")
	ErrNameTaken           = errors.New("name_taken")
	ErrOwnerViaGroup       = errors.New("owner_via_group")
	ErrMemberCountMismatch = errors.New("member_count_mismatch")
)

// Limits.
const (
	GroupNameMax        = 64
	GroupDescriptionMax = 500
	GroupBatchMax       = 100
)

// GroupStore is the persistence used by Groups (mirror rows next to OpenFGA).
type GroupStore interface {
	RolesByID(ctx context.Context, tenantID string, ids []string) ([]store.Role, error)
	RolePermissions(ctx context.Context, tenantID, roleID string) ([]PermissionRef, error)
	CreateGroup(ctx context.Context, g store.Group) error
	UpdateGroup(ctx context.Context, tenantID, id, name, description string) error
	DeleteGroup(ctx context.Context, tenantID, id string) error
	GetGroup(ctx context.Context, tenantID, id string) (store.Group, error)
	ListGroups(ctx context.Context, tenantID, q string) ([]store.Group, error)
	GroupMemberCounts(ctx context.Context, tenantID string) (map[string]int, error)
	CountGroupMembers(ctx context.Context, tenantID, groupID string) (int, error)
	ListGroupMembers(ctx context.Context, tenantID, groupID string, after time.Time, limit int) ([]store.GroupMember, error)
	AddGroupMembers(ctx context.Context, tenantID, groupID, addedBy string, userIDs []string) (int, error)
	RemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error
	IsGroupMember(ctx context.Context, tenantID, groupID, userID string) (bool, error)
	UserGroups(ctx context.Context, tenantID, userID string) ([]store.Group, error)
	ReplaceGroupRoles(ctx context.Context, tenantID, groupID, grantedBy string, roleIDs []string) error
	GroupRoles(ctx context.Context, tenantID, groupID string) ([]store.Role, error)
	GroupRoleSlugs(ctx context.Context, tenantID string) (map[string][]string, error)
	EffectiveRoles(ctx context.Context, tenantID, userID string) ([]store.EffectiveRoleRow, error)
}

// Groups manages tenant groups: mirror rows, OpenFGA tuples (membership and
// role assignment through the group userset), audit and the same escalation
// rules as direct role assignment.
type Groups struct {
	st    GroupStore
	authz *Client
	audit *audit.Writer
	esc   *Escalation
}

// NewGroups wires the service.
func NewGroups(st GroupStore, c *Client, a *audit.Writer) *Groups {
	return &Groups{st: st, authz: c, audit: a, esc: NewEscalation(c)}
}

// GroupView is a group with its roles and member count.
type GroupView struct {
	store.Group
	Roles       []string
	MemberCount int
}

// RoleSource explains why a user holds a role.
type RoleSource struct {
	Kind      string `json:"kind"` // direct | group
	GroupID   string `json:"group_id,omitempty"`
	GroupName string `json:"group_name,omitempty"`
}

// EffectiveRole is one role with every source that grants it.
type EffectiveRole struct {
	RoleID  string       `json:"role_id"`
	Slug    string       `json:"slug"`
	Sources []RoleSource `json:"sources"`
}

// admin returns the actor when it may manage groups (tenant owner/admin or
// system), auditing a refusal otherwise. Cross-tenant callers are refused by
// the guard first.
func (g *Groups) admin(ctx context.Context, tenantID string, typ audit.EventType, subjectKind, subjectID string) (tenantctx.Actor, error) {
	actor, ok := tenantctx.FromContext(ctx)
	if !ok {
		return actor, tenantctx.ErrNoActor
	}
	if err := g.authz.guard.Require(ctx, tenantID); err != nil {
		return actor, err
	}
	if actor.Kind == tenantctx.KindSystem || actor.IsAdmin() {
		return actor, nil
	}
	g.emit(audit.Event{Type: typ, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: ErrForbidden.Error(), SubjectKind: subjectKind, SubjectID: subjectID})
	return actor, ErrForbidden
}

// ValidateGroupName trims and checks a group name.
func ValidateGroupName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > GroupNameMax || hasControl(name) {
		return "", ErrInvalidName
	}
	return name, nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// Create adds an empty group.
func (g *Groups) Create(ctx context.Context, tenantID, name, description string) (store.Group, error) {
	actor, err := g.admin(ctx, tenantID, audit.GroupCreated, "group", "")
	if err != nil {
		return store.Group{}, err
	}
	name, err = ValidateGroupName(name)
	if err != nil {
		return store.Group{}, err
	}
	description = strings.TrimSpace(description)
	if len(description) > GroupDescriptionMax || hasControl(description) {
		return store.Group{}, ErrInvalidName
	}
	grp := store.Group{ID: store.NewID(), TenantID: tenantID, Name: name, Description: description}
	if actor.UserID != "" {
		uid := actor.UserID
		grp.CreatedBy = &uid
	}
	if err := g.st.CreateGroup(ctx, grp); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.Group{}, ErrNameTaken
		}
		return store.Group{}, err
	}
	if err := g.authz.Write(ctx, tenantID, []Tuple{GroupTenantTuple(tenantID, grp.ID)}, nil); err != nil {
		return store.Group{}, err
	}
	g.emit(audit.Event{Type: audit.GroupCreated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "group", SubjectID: grp.ID, Details: map[string]any{"name": grp.Name}})
	return grp, nil
}

// Update renames/describes a group.
func (g *Groups) Update(ctx context.Context, tenantID, id, name, description string) (store.Group, error) {
	actor, err := g.admin(ctx, tenantID, audit.GroupUpdated, "group", id)
	if err != nil {
		return store.Group{}, err
	}
	name, err = ValidateGroupName(name)
	if err != nil {
		return store.Group{}, err
	}
	description = strings.TrimSpace(description)
	if len(description) > GroupDescriptionMax || hasControl(description) {
		return store.Group{}, ErrInvalidName
	}
	if err := g.st.UpdateGroup(ctx, tenantID, id, name, description); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.Group{}, ErrNameTaken
		}
		return store.Group{}, err
	}
	g.emit(audit.Event{Type: audit.GroupUpdated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "group", SubjectID: id, Details: map[string]any{"name": name}})
	return g.st.GetGroup(ctx, tenantID, id)
}

// Delete removes a group after the caller confirms the current member count;
// every member loses the group's roles.
func (g *Groups) Delete(ctx context.Context, tenantID, id string, memberCount int) error {
	actor, err := g.admin(ctx, tenantID, audit.GroupDeleted, "group", id)
	if err != nil {
		return err
	}
	grp, err := g.st.GetGroup(ctx, tenantID, id)
	if err != nil {
		return err
	}
	n, err := g.st.CountGroupMembers(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if n != memberCount {
		g.emit(audit.Event{Type: audit.GroupDeleted, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: ErrMemberCountMismatch.Error(), SubjectKind: "group", SubjectID: id})
		return ErrMemberCountMismatch
	}
	roles, err := g.st.GroupRoles(ctx, tenantID, id)
	if err != nil {
		return err
	}
	removes := []Tuple{GroupTenantTuple(tenantID, id)}
	slugs := make([]string, 0, len(roles))
	for _, r := range roles {
		removes = append(removes, GroupRoleTuple(tenantID, id, r.Slug))
		slugs = append(slugs, r.Slug)
	}
	var after time.Time
	for {
		page, err := g.st.ListGroupMembers(ctx, tenantID, id, after, GroupBatchMax)
		if err != nil {
			return err
		}
		for _, m := range page {
			removes = append(removes, GroupMembershipTuple(tenantID, id, m.UserID))
			after = m.AddedAt
		}
		if len(page) < GroupBatchMax {
			break
		}
	}
	if err := g.st.DeleteGroup(ctx, tenantID, id); err != nil {
		return err
	}
	for start := 0; start < len(removes); start += GroupBatchMax {
		end := min(start+GroupBatchMax, len(removes))
		if err := g.authz.Write(ctx, tenantID, nil, removes[start:end]); err != nil {
			return err
		}
	}
	g.emit(audit.Event{Type: audit.GroupDeleted, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "group", SubjectID: id,
		Details: map[string]any{"name": grp.Name, "member_count": n, "roles": slugs}})
	return nil
}

// Get returns a group with its roles and member count.
func (g *Groups) Get(ctx context.Context, tenantID, id string) (GroupView, error) {
	if _, err := g.admin(ctx, tenantID, audit.GroupUpdated, "group", id); err != nil {
		return GroupView{}, err
	}
	grp, err := g.st.GetGroup(ctx, tenantID, id)
	if err != nil {
		return GroupView{}, err
	}
	roles, err := g.st.GroupRoles(ctx, tenantID, id)
	if err != nil {
		return GroupView{}, err
	}
	n, err := g.st.CountGroupMembers(ctx, tenantID, id)
	if err != nil {
		return GroupView{}, err
	}
	v := GroupView{Group: grp, Roles: []string{}, MemberCount: n}
	for _, r := range roles {
		v.Roles = append(v.Roles, r.Slug)
	}
	return v, nil
}

// List returns the tenant's groups with roles and member counts.
func (g *Groups) List(ctx context.Context, tenantID, q string) ([]GroupView, error) {
	if _, err := g.admin(ctx, tenantID, audit.GroupUpdated, "group", ""); err != nil {
		return nil, err
	}
	groups, err := g.st.ListGroups(ctx, tenantID, strings.TrimSpace(q))
	if err != nil {
		return nil, err
	}
	counts, err := g.st.GroupMemberCounts(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	slugs, err := g.st.GroupRoleSlugs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]GroupView, 0, len(groups))
	for _, grp := range groups {
		rs := slugs[grp.ID]
		if rs == nil {
			rs = []string{}
		}
		out = append(out, GroupView{Group: grp, Roles: rs, MemberCount: counts[grp.ID]})
	}
	return out, nil
}

// Members pages the members of a group.
func (g *Groups) Members(ctx context.Context, tenantID, id string, after time.Time, limit int) ([]store.GroupMember, error) {
	if _, err := g.admin(ctx, tenantID, audit.GroupUpdated, "group", id); err != nil {
		return nil, err
	}
	if _, err := g.st.GetGroup(ctx, tenantID, id); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > GroupBatchMax {
		limit = GroupBatchMax
	}
	return g.st.ListGroupMembers(ctx, tenantID, id, after, limit)
}

// UserGroups lists the groups of a user.
func (g *Groups) UserGroups(ctx context.Context, tenantID, userID string) ([]store.Group, error) {
	if _, err := g.admin(ctx, tenantID, audit.GroupUpdated, "user", userID); err != nil {
		return nil, err
	}
	return g.st.UserGroups(ctx, tenantID, userID)
}

// groupGrants returns the permissions the group's roles grant and whether the
// group carries the admin role.
func (g *Groups) groupGrants(ctx context.Context, tenantID, groupID string) ([]PermissionRef, bool, error) {
	roles, err := g.st.GroupRoles(ctx, tenantID, groupID)
	if err != nil {
		return nil, false, err
	}
	return g.roleGrants(ctx, tenantID, roles)
}

func (g *Groups) roleGrants(ctx context.Context, tenantID string, roles []store.Role) ([]PermissionRef, bool, error) {
	var perms []PermissionRef
	privileged := false
	for _, r := range roles {
		if r.Slug == "owner" || r.Slug == "admin" {
			privileged = true
		}
		ps, err := g.st.RolePermissions(ctx, tenantID, r.ID)
		if err != nil {
			return nil, false, err
		}
		perms = append(perms, ps...)
	}
	return perms, privileged, nil
}

// MayJoin returns ErrSelfEscalation unless the actor may grant everything
// the groups grant (owners and system actors always may), the check
// AddMembers makes, for groups an invitation names (feature 016). It writes
// nothing and emits no audit event; an unknown or foreign group is
// store.ErrNotFound.
func (g *Groups) MayJoin(ctx context.Context, actor tenantctx.Actor, tenantID string, groupIDs []string) error {
	var perms []PermissionRef
	for _, id := range dedupe(groupIDs) {
		if _, err := g.st.GetGroup(ctx, tenantID, id); err != nil {
			return err
		}
		ps, privileged, err := g.groupGrants(ctx, tenantID, id)
		if err != nil {
			return err
		}
		if privileged && !actor.IsOwner() && actor.Kind != tenantctx.KindSystem {
			return ErrSelfEscalation
		}
		perms = append(perms, ps...)
	}
	return g.esc.MayGrant(ctx, actor, tenantID, perms)
}

// AddMembers adds users to the group. The actor must be able to grant
// everything the group grants (owners always can); existing members are
// silent no-ops; a user outside the tenant is not found. Returns the number
// of users actually added.
func (g *Groups) AddMembers(ctx context.Context, tenantID, id string, userIDs []string) (int, error) {
	actor, err := g.admin(ctx, tenantID, audit.GroupMemberAdded, "group", id)
	if err != nil {
		return 0, err
	}
	if _, err := g.st.GetGroup(ctx, tenantID, id); err != nil {
		return 0, err
	}
	userIDs = dedupe(userIDs)
	if len(userIDs) == 0 || len(userIDs) > GroupBatchMax {
		return 0, ErrInvalidName
	}
	perms, privileged, err := g.groupGrants(ctx, tenantID, id)
	if err != nil {
		return 0, err
	}
	if privileged && !actor.IsOwner() && actor.Kind != tenantctx.KindSystem {
		return 0, g.refuse(actor, tenantID, audit.GroupMemberAdded, "group", id, ErrSelfEscalation)
	}
	if err := g.esc.MayGrant(ctx, actor, tenantID, perms); err != nil {
		if errors.Is(err, ErrSelfEscalation) {
			return 0, g.refuse(actor, tenantID, audit.GroupMemberAdded, "group", id, err)
		}
		return 0, err
	}
	added := 0
	var adds []Tuple
	for _, uid := range userIDs {
		member, err := g.st.IsGroupMember(ctx, tenantID, id, uid)
		if err != nil {
			return added, err
		}
		if member {
			continue
		}
		n, err := g.st.AddGroupMembers(ctx, tenantID, id, actor.UserID, []string{uid})
		if err != nil {
			return added, err
		}
		if n == 0 {
			continue
		}
		added++
		adds = append(adds, GroupMembershipTuple(tenantID, id, uid))
		g.emit(audit.Event{Type: audit.GroupMemberAdded, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "user", SubjectID: uid, Details: map[string]any{"group": id}})
	}
	if len(adds) > 0 {
		if err := g.authz.Write(ctx, tenantID, adds, nil); err != nil {
			return added, err
		}
	}
	return added, nil
}

// RemoveMember removes a user from the group (idempotent).
func (g *Groups) RemoveMember(ctx context.Context, tenantID, id, userID string) error {
	actor, err := g.admin(ctx, tenantID, audit.GroupMemberRemoved, "group", id)
	if err != nil {
		return err
	}
	if _, err := g.st.GetGroup(ctx, tenantID, id); err != nil {
		return err
	}
	member, err := g.st.IsGroupMember(ctx, tenantID, id, userID)
	if err != nil {
		return err
	}
	if !member {
		return nil
	}
	if err := g.st.RemoveGroupMember(ctx, tenantID, id, userID); err != nil {
		return err
	}
	if err := g.authz.Write(ctx, tenantID, nil, []Tuple{GroupMembershipTuple(tenantID, id, userID)}); err != nil {
		return err
	}
	g.emit(audit.Event{Type: audit.GroupMemberRemoved, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "user", SubjectID: userID, Details: map[string]any{"group": id}})
	return nil
}

// SetRoles replaces the group's roles. Owner is never assignable through a
// group; non-owners cannot grant admin nor permissions they lack.
func (g *Groups) SetRoles(ctx context.Context, tenantID, id string, roleIDs []string) ([]string, error) {
	actor, err := g.admin(ctx, tenantID, audit.GroupRoleGranted, "group", id)
	if err != nil {
		return nil, err
	}
	if _, err := g.st.GetGroup(ctx, tenantID, id); err != nil {
		return nil, err
	}
	roleIDs = dedupe(roleIDs)
	if len(roleIDs) > GroupBatchMax {
		return nil, ErrInvalidName
	}
	want, err := g.st.RolesByID(ctx, tenantID, roleIDs)
	if err != nil {
		return nil, err
	}
	have, err := g.st.GroupRoles(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	var adding []store.Role
	for _, r := range want {
		if r.Slug == "owner" {
			return nil, g.refuse(actor, tenantID, audit.GroupRoleGranted, "group", id, ErrOwnerViaGroup)
		}
		if !containsRole(have, r.ID) {
			adding = append(adding, r)
		}
	}
	if err := refuseRetired(adding); err != nil {
		return nil, g.refuse(actor, tenantID, audit.GroupRoleGranted, "group", id, err)
	}
	perms, privileged, err := g.roleGrants(ctx, tenantID, adding)
	if err != nil {
		return nil, err
	}
	if privileged && !actor.IsOwner() && actor.Kind != tenantctx.KindSystem {
		return nil, g.refuse(actor, tenantID, audit.GroupRoleGranted, "group", id, ErrSelfEscalation)
	}
	if err := g.esc.MayGrant(ctx, actor, tenantID, perms); err != nil {
		if errors.Is(err, ErrSelfEscalation) {
			return nil, g.refuse(actor, tenantID, audit.GroupRoleGranted, "group", id, err)
		}
		return nil, err
	}
	ids := make([]string, 0, len(want))
	slugs := make([]string, 0, len(want))
	var adds, removes []Tuple
	for _, r := range want {
		ids = append(ids, r.ID)
		slugs = append(slugs, r.Slug)
		if !containsRole(have, r.ID) {
			adds = append(adds, GroupRoleTuple(tenantID, id, r.Slug))
		}
	}
	for _, r := range have {
		if !containsRole(want, r.ID) {
			removes = append(removes, GroupRoleTuple(tenantID, id, r.Slug))
		}
	}
	if err := g.st.ReplaceGroupRoles(ctx, tenantID, id, actor.UserID, ids); err != nil {
		return nil, err
	}
	if err := g.authz.Write(ctx, tenantID, adds, removes); err != nil {
		return nil, err
	}
	for _, t := range adds {
		g.emit(audit.Event{Type: audit.GroupRoleGranted, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "group", SubjectID: id, Details: map[string]any{"role": t.Object}})
	}
	for _, t := range removes {
		g.emit(audit.Event{Type: audit.GroupRoleRevoked, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "group", SubjectID: id, Details: map[string]any{"role": t.Object}})
	}
	return slugs, nil
}

// EffectiveRoles folds the user's (role, source) rows into one entry per role.
func (g *Groups) EffectiveRoles(ctx context.Context, tenantID, userID string) ([]EffectiveRole, error) {
	if _, err := g.admin(ctx, tenantID, audit.GroupUpdated, "user", userID); err != nil {
		return nil, err
	}
	rows, err := g.st.EffectiveRoles(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	return FoldEffectiveRoles(rows), nil
}

// FoldEffectiveRoles groups rows by role, keeping the source order (direct
// first, then groups by name) and dropping duplicate sources.
func FoldEffectiveRoles(rows []store.EffectiveRoleRow) []EffectiveRole {
	out := make([]EffectiveRole, 0)
	index := map[string]int{}
	for _, r := range rows {
		i, ok := index[r.RoleID]
		if !ok {
			index[r.RoleID] = len(out)
			out = append(out, EffectiveRole{RoleID: r.RoleID, Slug: r.Slug, Sources: []RoleSource{}})
			i = len(out) - 1
		}
		src := RoleSource{Kind: r.Source, GroupID: r.GroupID, GroupName: r.GroupName}
		dup := false
		for _, s := range out[i].Sources {
			if s == src {
				dup = true
			}
		}
		if !dup {
			out[i].Sources = append(out[i].Sources, src)
		}
	}
	return out
}

func (g *Groups) refuse(actor tenantctx.Actor, tenantID string, typ audit.EventType, subjectKind, subjectID string, err error) error {
	g.emit(audit.Event{Type: typ, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: err.Error(), SubjectKind: subjectKind, SubjectID: subjectID})
	return err
}

func (g *Groups) emit(e audit.Event) {
	if g.audit != nil {
		_ = g.audit.Emit(e)
	}
}
