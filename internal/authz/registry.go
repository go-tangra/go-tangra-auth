package authz

import (
	"context"
	"errors"
	"sort"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/permref"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// PermissionStore persists the per-tenant permission catalogue.
type PermissionStore interface {
	UpsertPermission(ctx context.Context, tenantID string, p store.Permission, registeredBy string) error
	ListPermissions(ctx context.Context, tenantID string) ([]store.Permission, error)
	// Modules lists the platform catalogue's modules (display names, retirement).
	Modules(ctx context.Context) ([]store.Module, error)
}

// Permission is a permission a module registers: resource, action and a
// description; the module comes from the registration.
type Permission struct {
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

// Ref returns the permission under module m ("" = legacy).
func (p Permission) Ref(m string) PermissionRef {
	return PermissionRef{Module: m, Resource: p.Resource, Action: p.Action}
}

// AuthModule is the module name of auth's own permissions.
const AuthModule = "auth"

// Display names used when the catalogue has none.
const (
	AuthDisplayName   = "Authentication"
	LegacyDisplayName = "Before modules"
)

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

// Register upserts permissions of module ("" = legacy rows, the pre-019
// behaviour kept for an old gateway) for one tenant (idempotent) and records
// the registering service. Each permission object gets its tenant tuple so
// roles can be granted it; tuples are written before the rows, and writes are
// idempotent, so a failure is repaired by the next registration.
func (r *Registry) Register(ctx context.Context, tenantID, module, registrant string, defs []Permission) (int, error) {
	if err := r.authz.guard.Require(ctx, tenantID); err != nil {
		return 0, err
	}
	if module != "" && !permref.ValidModule(module) {
		return 0, ErrBadPermission
	}
	refs := make([]PermissionRef, 0, len(defs))
	for _, d := range defs {
		if !permref.ValidResource(d.Resource) || !permref.ValidAction(d.Action) || len(d.Description) > 256 {
			return 0, ErrBadPermission
		}
		refs = append(refs, d.Ref(module))
	}
	existing, err := r.st.ListPermissions(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	known := map[PermissionRef]bool{}
	for _, p := range existing {
		known[p.Ref()] = true
	}
	var tuples []Tuple
	for _, ref := range refs {
		if !known[ref] {
			known[ref] = true
			tuples = append(tuples, PermissionTenantTuple(tenantID, ref))
		}
	}
	if len(tuples) > 0 {
		if err := r.authz.Write(ctx, tenantID, tuples, nil); err != nil {
			return 0, err
		}
	}
	for i, d := range defs {
		p := store.Permission{Module: module, Resource: refs[i].Resource, Action: refs[i].Action, Description: d.Description}
		if err := r.st.UpsertPermission(ctx, tenantID, p, registrant); err != nil {
			return 0, err
		}
	}
	if len(defs) > 0 {
		r.emit(audit.Event{Type: audit.PermissionRegistered, TenantID: tenantID, ActorKind: "service", ActorService: registrant, Outcome: "ok", Details: map[string]any{"count": len(defs), "module": module}})
	}
	return len(defs), nil
}

// CatalogueEntry is one permission as the role editor shows it (feature 019).
type CatalogueEntry struct {
	Ref               string `json:"ref"`
	Module            string `json:"module"`
	ModuleDisplayName string `json:"module_display_name"`
	Resource          string `json:"resource"`
	Action            string `json:"action"`
	Description       string `json:"description"`
	Grantable         bool   `json:"grantable"`
	Legacy            bool   `json:"legacy"`
}

// ModuleDisplayNames maps module names to display names ("auth" is
// "Authentication" unless the catalogue says otherwise) and reports retired
// modules.
func ModuleDisplayNames(mods []store.Module) (names map[string]string, retired map[string]bool) {
	names, retired = map[string]string{AuthModule: AuthDisplayName}, map[string]bool{}
	for _, m := range mods {
		if m.Name != AuthModule || m.DisplayName != m.Name {
			names[m.Name] = m.DisplayName
		}
		if m.RetiredAt != nil {
			retired[m.Name] = true
		}
	}
	return names, retired
}

// DisplayName returns the display name of module m.
func DisplayName(names map[string]string, m string) string {
	if m == "" {
		return LegacyDisplayName
	}
	if n, ok := names[m]; ok && n != "" {
		return n
	}
	return m
}

// Catalogue lists the tenant's permissions with module display names, sorted
// by display name, resource and action (legacy rows last), without retired
// modules. Grantable says whether the actor may grant the permission: owners
// and the system may grant everything, anyone else what they hold.
func (r *Registry) Catalogue(ctx context.Context, tenantID string, actor tenantctx.Actor) ([]CatalogueEntry, error) {
	if err := r.authz.guard.Require(ctx, tenantID); err != nil {
		return nil, err
	}
	rows, err := r.st.ListPermissions(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	mods, err := r.st.Modules(ctx)
	if err != nil {
		return nil, err
	}
	names, retired := ModuleDisplayNames(mods)
	out := make([]CatalogueEntry, 0, len(rows))
	for _, p := range rows {
		if retired[p.Module] {
			continue
		}
		out = append(out, CatalogueEntry{Ref: p.Ref().String(), Module: p.Module, ModuleDisplayName: DisplayName(names, p.Module),
			Resource: p.Resource, Action: p.Action, Description: p.Description, Legacy: p.Module == ""})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Legacy != b.Legacy {
			return !a.Legacy
		}
		if a.ModuleDisplayName != b.ModuleDisplayName {
			return a.ModuleDisplayName < b.ModuleDisplayName
		}
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		return a.Action < b.Action
	})
	if actor.Kind == tenantctx.KindSystem || hasSlug(actor.Roles, "owner") {
		for i := range out {
			out[i].Grantable = true
		}
		return out, nil
	}
	for start := 0; start < len(out); start += MaxTuplesPerWrite {
		end := min(start+MaxTuplesPerWrite, len(out))
		refs := make([]PermissionRef, 0, end-start)
		for _, e := range out[start:end] {
			refs = append(refs, PermissionRef{Module: e.Module, Resource: e.Resource, Action: e.Action})
		}
		held, err := r.authz.AllowedMany(ctx, tenantID, actor.UserID, refs)
		if err != nil {
			return nil, err
		}
		for i, ok := range held {
			out[start+i].Grantable = ok
		}
	}
	return out, nil
}

func (r *Registry) emit(e audit.Event) {
	if r.audit != nil {
		_ = r.audit.Emit(e)
	}
}
