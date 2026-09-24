package authz

import (
	"context"
	"strconv"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// Decision reasons (auth.v1.CheckResponse.reason vocabulary).
const (
	ReasonNoPermission      = "no_permission"
	ReasonUserInactive      = "user_inactive"
	ReasonTenantSuspended   = "tenant_suspended"
	ReasonUnknownPermission = "unknown_permission"
)

// StatusStore answers the status checks a decision needs.
type StatusStore interface {
	UserStatus(ctx context.Context, tenantID, userID string) (string, error)
	TenantStatus(ctx context.Context, tenantID string) (string, error)
	ListPermissions(ctx context.Context, tenantID string) ([][3]string, error)
	UserRoles(ctx context.Context, tenantID, userID string) ([]store.Role, error)
	RolePermissions(ctx context.Context, tenantID, roleID string) ([][2]string, error)
	// EffectiveRoles includes roles inherited through groups (feature 004).
	EffectiveRoles(ctx context.Context, tenantID, userID string) ([]store.EffectiveRoleRow, error)
}

// Decision is the answer to one check.
type Decision struct {
	Allowed       bool
	Reason        string // role:<slug> when allowed
	PolicyVersion string
}

// Decider evaluates permissions with status checks, the tenant guard and a
// short decision cache keyed by the tenant version.
type Decider struct {
	st    StatusStore
	authz *Client
	audit *audit.Writer
}

// NewDecider wires the decider.
func NewDecider(st StatusStore, c *Client, a *audit.Writer) *Decider {
	return &Decider{st: st, authz: c, audit: a}
}

// Decide answers one permission check for a user in a tenant.
func (d *Decider) Decide(ctx context.Context, tenantID, userID string, p PermissionRef) (Decision, error) {
	res, err := d.BatchDecide(ctx, tenantID, userID, []PermissionRef{p})
	if err != nil {
		return Decision{}, err
	}
	return res[0], nil
}

// BatchDecide evaluates several permissions for the same user.
func (d *Decider) BatchDecide(ctx context.Context, tenantID, userID string, perms []PermissionRef) ([]Decision, error) {
	if err := d.authz.guard.Require(ctx, tenantID); err != nil {
		return nil, err
	}
	version := ""
	if d.authz.cache != nil {
		if v, err := d.authz.cache.TenantVersion(ctx, tenantID); err == nil {
			version = strconv.FormatInt(v, 10)
		}
	}
	deny := func(reason string) []Decision {
		out := make([]Decision, len(perms))
		for i := range out {
			out[i] = Decision{Reason: reason, PolicyVersion: version}
		}
		return out
	}
	ts, err := d.st.TenantStatus(ctx, tenantID)
	if err != nil || ts != "active" {
		return deny(ReasonTenantSuspended), nil
	}
	us, err := d.st.UserStatus(ctx, tenantID, userID)
	if err != nil || us != "active" {
		return deny(ReasonUserInactive), nil
	}
	catalogue, err := d.st.ListPermissions(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, p := range catalogue {
		known[p[0]+":"+p[1]] = true
	}
	out := make([]Decision, len(perms))
	var ask []int
	var askRefs []PermissionRef
	for i, p := range perms {
		out[i] = Decision{Reason: ReasonNoPermission, PolicyVersion: version}
		if !known[p.String()] {
			out[i].Reason = ReasonUnknownPermission
			continue
		}
		if d.authz.cache != nil {
			key := cache.DecisionKey(tenantID, userID, p.String()+"@"+version)
			if v, ok, _ := d.authz.cache.KV().Get(ctx, key); ok {
				out[i].Allowed = v != "0"
				if out[i].Allowed {
					out[i].Reason = v
				}
				continue
			}
		}
		ask = append(ask, i)
		askRefs = append(askRefs, p)
	}
	if len(ask) > 0 {
		allowed, err := d.authz.AllowedMany(ctx, tenantID, userID, askRefs)
		if err != nil {
			return nil, err
		}
		var roles []store.Role
		for j, i := range ask {
			if allowed[j] {
				if roles == nil {
					roles = d.effectiveRoles(ctx, tenantID, userID)
				}
				out[i].Allowed = true
				out[i].Reason = d.grantingRole(ctx, tenantID, roles, askRefs[j])
			}
			if d.authz.cache != nil {
				v := "0"
				if out[i].Allowed {
					v = out[i].Reason
				}
				_ = d.authz.cache.KV().Set(ctx, cache.DecisionKey(tenantID, userID, askRefs[j].String()+"@"+version), v, DecisionTTL)
			}
		}
	}
	for i, dec := range out {
		if !dec.Allowed {
			d.emit(audit.Event{Type: audit.AuthzDenied, TenantID: tenantID, ActorKind: "user", ActorUserID: userID, Outcome: "refused", Reason: dec.Reason, SubjectKind: "permission", Details: map[string]any{"permission": perms[i].String()}})
		}
	}
	return out, nil
}

// effectiveRoles lists the user's roles including those held through groups,
// deduplicated by id; direct roles come first.
func (d *Decider) effectiveRoles(ctx context.Context, tenantID, userID string) []store.Role {
	rows, err := d.st.EffectiveRoles(ctx, tenantID, userID)
	if err != nil {
		roles, _ := d.st.UserRoles(ctx, tenantID, userID)
		return roles
	}
	seen := map[string]bool{}
	out := make([]store.Role, 0, len(rows))
	for _, r := range rows {
		if !seen[r.RoleID] {
			seen[r.RoleID] = true
			out = append(out, store.Role{ID: r.RoleID, TenantID: tenantID, Slug: r.Slug})
		}
	}
	return out
}

// grantingRole names the first role of the user that grants p (mirror rows).
func (d *Decider) grantingRole(ctx context.Context, tenantID string, roles []store.Role, p PermissionRef) string {
	for _, r := range roles {
		perms, err := d.st.RolePermissions(ctx, tenantID, r.ID)
		if err != nil {
			continue
		}
		for _, x := range perms {
			if x[0] == p.Resource && x[1] == p.Action {
				return "role:" + r.Slug
			}
		}
	}
	return "role:unknown"
}

func (d *Decider) emit(e audit.Event) {
	if d.audit != nil {
		_ = d.audit.Emit(e)
	}
}

// ErrNotFound re-exported for callers mapping decisions.
var ErrNotFound = store.ErrNotFound
