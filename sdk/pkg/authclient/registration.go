package authclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"google.golang.org/grpc"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
)

// Registration limits enforced by auth (feature 019).
const (
	MaxPermissions     = 200
	MaxRoles           = 20
	MaxRolePermissions = 200
)

// ErrInvalidRegistration is returned by Validate (and Register) for a
// registration auth would refuse; nothing is sent.
var ErrInvalidRegistration = errors.New("authclient: invalid registration")

var (
	moduleRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	resourceRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	actionRE   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	roleSlugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)
	tenantRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// builtinRoles may receive built-in grants.
var builtinRoles = map[string]bool{"owner": true, "admin": true, "member": true, "auditor": true, "operator": true}

// Permission is one permission a module enforces.
type Permission struct {
	Resource, Action, Description string
}

// ModuleRole is a ready-made role the module provides in every tenant. It is
// locked in auth (administrators assign or clone it); Permissions are
// "resource:action" references of the same registration.
type ModuleRole struct {
	Slug, DisplayName, Description string
	Permissions                    []string
}

// Registration is what a module registers with auth
// (auth.v1.Authorization/RegisterPermissions, feature 019). Module must be
// the module's service name (the one in its SPIFFE identity).
type Registration struct {
	Module, DisplayName string
	Permissions         []Permission
	// Roles is the module's complete role set: roles it no longer lists are
	// retired in auth (kept for existing assignments).
	Roles []ModuleRole
	// BuiltinGrants maps built-in role slugs (owner, admin, member, auditor,
	// operator) to "resource:action" references of this registration.
	BuiltinGrants map[string][]string
	// TenantIDs limits the registration (empty: every active tenant).
	TenantIDs []string
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidRegistration}, args...)...)
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

// short returns "resource:action" for a short or own-module qualified ref.
func (r Registration) short(ref string) string {
	if parts := strings.Split(ref, ":"); len(parts) == 3 && parts[0] == r.Module {
		return parts[1] + ":" + parts[2]
	}
	return ref
}

// Validate checks limits, grammars and that roles and grants only name
// permissions of this registration (auth enforces the same rules).
func (r Registration) Validate() error {
	if !moduleRE.MatchString(r.Module) {
		return invalid("module %q", r.Module)
	}
	if !printable(r.DisplayName, 120) {
		return invalid("display name")
	}
	if len(r.Permissions) > MaxPermissions {
		return invalid("%d permissions (max %d)", len(r.Permissions), MaxPermissions)
	}
	own := map[string]bool{}
	for _, p := range r.Permissions {
		ref := p.Resource + ":" + p.Action
		if !resourceRE.MatchString(p.Resource) || !actionRE.MatchString(p.Action) || !printable(p.Description, 256) {
			return invalid("permission %q", ref)
		}
		if own[ref] {
			return invalid("duplicate permission %q", ref)
		}
		own[ref] = true
	}
	if len(r.Roles) > MaxRoles {
		return invalid("%d roles (max %d)", len(r.Roles), MaxRoles)
	}
	slugs := map[string]bool{}
	for _, role := range r.Roles {
		name := strings.TrimSpace(role.DisplayName)
		switch {
		case !roleSlugRE.MatchString(role.Slug):
			return invalid("role slug %q", role.Slug)
		case slugs[role.Slug]:
			return invalid("duplicate role %q", role.Slug)
		case name == "" || !printable(name, 120) || !printable(role.Description, 256):
			return invalid("role %q: display name or description", role.Slug)
		case len(role.Permissions) == 0 || len(role.Permissions) > MaxRolePermissions:
			return invalid("role %q: %d permissions (1–%d)", role.Slug, len(role.Permissions), MaxRolePermissions)
		}
		slugs[role.Slug] = true
		for _, p := range role.Permissions {
			if !own[r.short(p)] {
				return invalid("role %q names %q, not a permission of this registration", role.Slug, p)
			}
		}
	}
	for role, refs := range r.BuiltinGrants {
		if !builtinRoles[role] {
			return invalid("built-in grant to %q", role)
		}
		for _, p := range refs {
			if !own[p] {
				return invalid("built-in grant %q → %q, not a permission of this registration", role, p)
			}
		}
	}
	for _, t := range r.TenantIDs {
		if !tenantRE.MatchString(t) {
			return invalid("tenant id %q", t)
		}
	}
	return nil
}

// Request renders the registration (declares_roles: Roles is the complete
// set; grants sorted by role for stable requests).
func (r Registration) Request() *authv1.RegisterPermissionsRequest {
	req := &authv1.RegisterPermissionsRequest{Module: r.Module, ModuleDisplayName: r.DisplayName, DeclaresRoles: true, TenantIds: r.TenantIDs}
	for _, p := range r.Permissions {
		req.Permissions = append(req.Permissions, &authv1.PermissionDef{Resource: p.Resource, Action: p.Action, Description: p.Description})
	}
	for _, role := range r.Roles {
		def := &authv1.ModuleRoleDef{Slug: role.Slug, DisplayName: strings.TrimSpace(role.DisplayName), Description: role.Description}
		for _, p := range role.Permissions {
			def.Permissions = append(def.Permissions, r.short(p))
		}
		req.Roles = append(req.Roles, def)
	}
	roles := make([]string, 0, len(r.BuiltinGrants))
	for role := range r.BuiltinGrants {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		req.BuiltinGrants = append(req.BuiltinGrants, &authv1.BuiltinGrant{Role: role, Permissions: append([]string(nil), r.BuiltinGrants[role]...)})
	}
	return req
}

// Register validates the registration, sends it over cc (the mesh
// connection to auth) and logs every skipped built-in grant (warn) and
// rejected role (error). Modules call it at start and periodically.
func (r Registration) Register(ctx context.Context, cc grpc.ClientConnInterface, log *slog.Logger) (*authv1.RegisterPermissionsResponse, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	resp, err := authv1.NewAuthorizationClient(cc).RegisterPermissions(ctx, r.Request())
	if err != nil {
		return nil, fmt.Errorf("authclient: register permissions: %w", err)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	for _, s := range resp.GetSkippedGrants() {
		log.Warn("auth registration: built-in grant skipped", "module", r.Module, "role", s.GetRole(), "tenants", s.GetTenants(), "sample", s.GetSampleTenantIds(), "reason", s.GetReason())
	}
	for _, e := range resp.GetRoleErrors() {
		log.Error("auth registration: module role rejected", "module", r.Module, "slug", e.GetSlug(), "reason", e.GetReason())
	}
	if len(resp.GetRolesRetired()) > 0 {
		log.Info("auth registration: module roles retired", "module", r.Module, "roles", resp.GetRolesRetired())
	}
	return resp, nil
}
