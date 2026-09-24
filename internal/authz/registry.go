package authz

import (
	"context"
	"errors"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
)

// PermissionStore persists the per-tenant permission catalogue.
type PermissionStore interface {
	UpsertPermission(ctx context.Context, tenantID, resource, action, description, registeredBy string) error
	ListPermissions(ctx context.Context, tenantID string) ([][3]string, error)
}

// Permission is a catalogue entry.
type Permission struct {
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

// Ref renders "resource:action".
func (p Permission) Ref() PermissionRef { return PermissionRef{Resource: p.Resource, Action: p.Action} }

// Registry lets platform services declare the permissions they enforce.
type Registry struct {
	st    PermissionStore
	authz *Client
	audit *audit.Writer
}

// NewRegistry wires the registry.
func NewRegistry(st PermissionStore, c *Client, a *audit.Writer) *Registry {
	return &Registry{st: st, authz: c, audit: a}
}

// ErrBadPermission is returned for malformed definitions.
var ErrBadPermission = errors.New("authz: invalid permission")

// Register upserts permissions for one tenant (idempotent) and records the
// registering service. Each permission object gets its tenant tuple so roles
// can be granted it.
func (r *Registry) Register(ctx context.Context, tenantID, registrant string, defs []Permission) (int, error) {
	if err := r.authz.guard.Require(ctx, tenantID); err != nil {
		return 0, err
	}
	refs := make([]PermissionRef, 0, len(defs))
	for _, d := range defs {
		ref, err := ParsePermissionRef(d.Resource + ":" + d.Action)
		if err != nil || len(d.Description) > 256 {
			return 0, ErrBadPermission
		}
		refs = append(refs, ref)
	}
	// Tuples are written only for permissions new to the tenant: OpenFGA
	// refuses duplicate writes and registration must be idempotent.
	existing, err := r.st.ListPermissions(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	known := map[string]bool{}
	for _, p := range existing {
		known[p[0]+":"+p[1]] = true
	}
	var tuples []Tuple
	for i, d := range defs {
		if err := r.st.UpsertPermission(ctx, tenantID, refs[i].Resource, refs[i].Action, d.Description, registrant); err != nil {
			return 0, err
		}
		if !known[refs[i].String()] {
			tuples = append(tuples, PermissionTenantTuple(tenantID, refs[i]))
		}
	}
	if len(tuples) > 0 {
		if err := r.authz.Write(ctx, tenantID, tuples, nil); err != nil {
			return 0, err
		}
	}
	if len(defs) > 0 {
		r.emit(audit.Event{Type: audit.PermissionRegistered, TenantID: tenantID, ActorKind: "service", ActorService: registrant, Outcome: "ok", Details: map[string]any{"count": len(defs)}})
	}
	return len(defs), nil
}

// List returns the catalogue of a tenant.
func (r *Registry) List(ctx context.Context, tenantID string) ([]Permission, error) {
	rows, err := r.st.ListPermissions(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Permission, 0, len(rows))
	for _, p := range rows {
		out = append(out, Permission{Resource: p[0], Action: p[1], Description: p[2]})
	}
	return out, nil
}

func (r *Registry) emit(e audit.Event) {
	if r.audit != nil {
		_ = r.audit.Emit(e)
	}
}
