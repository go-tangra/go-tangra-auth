package grpcapi

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/permref"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra/v4/authn"
)

// AuthorizationServer serves auth.v1.Authorization for platform services.
type AuthorizationServer struct {
	authv1.UnimplementedAuthorizationServer
	Decider  *authz.Decider
	Registry *authz.Registry
	// Tenants lists the tenants a registrant may register for when the
	// request names none (nil = require explicit tenant ids).
	Tenants func(ctx context.Context) ([]string, error)
	// Roles applies builtin_grants (nil = grants refused).
	Roles *authz.Roles
	// Modules applies module-scoped registrations (feature 019; nil = only
	// the legacy path of an old gateway).
	Modules *authz.Modules
	// Gateway is the gateway's service name (config gateway.service): the
	// only caller that may name another module (feature 019, D7).
	Gateway string
	Audit   *audit.Writer
	Log     *slog.Logger
}

// errModuleMismatch refuses a module ≠ caller from a service other than the gateway.
var errModuleMismatch = status.Error(codes.PermissionDenied, "module_mismatch")

// caller is the verified identity of the calling service.
type caller struct {
	id      string // SPIFFE id
	module  string // service name ("" when the identity is not svc/<name>)
	gateway bool
}

// serviceCtx places the verified service peer as the actor and returns its
// SPIFFE id ("" without a peer).
func serviceCtx(ctx context.Context) (context.Context, string) {
	p, ok := authn.FromContext(ctx)
	if !ok {
		return ctx, ""
	}
	return tenantctx.WithActor(ctx, tenantctx.ActorFromService(p)), p.ID.String()
}

func (s *AuthorizationServer) serviceCtx(ctx context.Context) (context.Context, caller) {
	p, ok := authn.FromContext(ctx)
	if !ok {
		return ctx, caller{}
	}
	c := caller{id: p.ID.String()}
	if m, err := permref.ModuleFromSPIFFE(c.id); err == nil {
		c.module = m
		gw := s.Gateway
		if gw == "" {
			gw = "gateway"
		}
		c.gateway = m == gw
	}
	return tenantctx.WithActor(ctx, tenantctx.ActorFromService(p)), c
}

// checkModule resolves the module a check refers to (contracts/grpc.md):
// the gateway names it or asks about the legacy object; any other service
// asks about its own module, explicitly or not.
func (c caller) checkModule(requested string) (string, error) {
	switch {
	case requested == "" && c.gateway:
		return "", nil
	case requested == "":
		return c.module, nil // "" for non-svc identities: legacy, as before 019
	case !permref.ValidModule(requested):
		return "", status.Error(codes.InvalidArgument, "malformed module")
	case c.gateway || requested == c.module:
		return requested, nil
	}
	return "", errModuleMismatch
}

func (s *AuthorizationServer) Check(ctx context.Context, req *authv1.CheckRequest) (*authv1.CheckResponse, error) {
	ctx, c := s.serviceCtx(ctx)
	module, err := c.checkModule(req.GetModule())
	if err != nil {
		return nil, err
	}
	ref, err := authz.ParsePermissionRef(req.GetResource() + ":" + req.GetAction())
	if err != nil || !ref.IsLegacy() || !tenantctx.ValidTenantID(req.GetTenantId()) || req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "malformed request")
	}
	d, err := s.Decider.Decide(ctx, req.GetTenantId(), req.GetUserId(), ref.WithModule(module))
	if err != nil {
		return nil, decisionError(err)
	}
	return &authv1.CheckResponse{Allowed: d.Allowed, Reason: d.Reason, PolicyVersion: d.PolicyVersion}, nil
}

func (s *AuthorizationServer) BatchCheck(ctx context.Context, req *authv1.BatchCheckRequest) (*authv1.BatchCheckResponse, error) {
	ctx, c := s.serviceCtx(ctx)
	if !tenantctx.ValidTenantID(req.GetTenantId()) || req.GetUserId() == "" || len(req.GetPermissions()) == 0 || len(req.GetPermissions()) > 100 {
		return nil, status.Error(codes.InvalidArgument, "malformed request")
	}
	refs := make([]authz.PermissionRef, 0, len(req.GetPermissions()))
	for _, p := range req.GetPermissions() {
		module, err := c.checkModule(p.GetModule())
		if err != nil {
			return nil, err
		}
		ref, err := authz.ParsePermissionRef(p.GetResource() + ":" + p.GetAction())
		if err != nil || !ref.IsLegacy() {
			return nil, status.Error(codes.InvalidArgument, "malformed permission")
		}
		refs = append(refs, ref.WithModule(module))
	}
	ds, err := s.Decider.BatchDecide(ctx, req.GetTenantId(), req.GetUserId(), refs)
	if err != nil {
		return nil, decisionError(err)
	}
	out := &authv1.BatchCheckResponse{}
	for _, d := range ds {
		out.Results = append(out.Results, &authv1.CheckResponse{Allowed: d.Allowed, Reason: d.Reason, PolicyVersion: d.PolicyVersion})
	}
	return out, nil
}

// RegisterPermissions registers a module's permissions, roles and built-in
// grants (feature 019, contracts/grpc.md): the module is the caller's service
// name unless the gateway registers on behalf of a module it proxies (then
// without roles or grants); an old gateway without a module updates legacy
// rows only; a registration for "auth" from the gateway changes nothing.
func (s *AuthorizationServer) RegisterPermissions(ctx context.Context, req *authv1.RegisterPermissionsRequest) (*authv1.RegisterPermissionsResponse, error) {
	ctx, c := s.serviceCtx(ctx)
	if c.id == "" {
		return nil, status.Error(codes.Unauthenticated, "service identity required")
	}
	if c.module == "" {
		return nil, status.Error(codes.PermissionDenied, "service identity required")
	}
	module := req.GetModule()
	switch {
	case module != "" && !permref.ValidModule(module):
		return nil, status.Error(codes.InvalidArgument, "malformed module")
	case module != "" && module != c.module && !c.gateway:
		s.emit(audit.Event{Type: audit.ModuleRegistered, TenantID: s.auditTenant(req), ActorKind: "service", ActorService: c.id, Outcome: "refused", Reason: "module_mismatch",
			SubjectKind: "module", Details: map[string]any{"module": module, "caller": c.module}})
		return nil, errModuleMismatch
	}
	if c.gateway && (len(req.GetRoles()) > 0 || req.GetDeclaresRoles() || len(req.GetBuiltinGrants()) > 0) {
		return nil, status.Error(codes.InvalidArgument, "the gateway may not register roles or grants")
	}
	if len(req.GetPermissions()) > authz.MaxRegistrationPermissions || len(req.GetRoles()) > authz.MaxModuleRoles {
		return nil, status.Error(codes.InvalidArgument, "too many permissions or roles")
	}
	defs := make([]authz.Permission, 0, len(req.GetPermissions()))
	own := map[string]bool{}
	for _, p := range req.GetPermissions() {
		defs = append(defs, authz.Permission{Resource: p.GetResource(), Action: p.GetAction(), Description: p.GetDescription()})
		own[p.GetResource()+":"+p.GetAction()] = true
	}
	// Grants may only name the registrant's own permissions from this request.
	grants := make([]authz.BuiltinGrant, 0, len(req.GetBuiltinGrants()))
	for _, g := range req.GetBuiltinGrants() {
		if s.Roles == nil || !authz.BuiltinRoleSlugs[g.GetRole()] {
			return nil, status.Error(codes.InvalidArgument, "builtin_grants: unknown role")
		}
		for _, p := range g.GetPermissions() {
			if !own[p] {
				return nil, status.Error(codes.InvalidArgument, "builtin_grants: permission not registered by this request")
			}
		}
		grants = append(grants, authz.BuiltinGrant{Role: g.GetRole(), Permissions: g.GetPermissions()})
	}
	if c.gateway && module == authz.AuthModule {
		// auth registers its own permissions in-process; nothing to refresh.
		return &authv1.RegisterPermissionsResponse{}, nil
	}
	tenants := req.GetTenantIds()
	if len(tenants) == 0 {
		if s.Tenants == nil {
			return nil, status.Error(codes.InvalidArgument, "tenant_ids required")
		}
		var err error
		if tenants, err = s.Tenants(ctx); err != nil {
			return nil, status.Error(codes.Unavailable, "tenants unavailable")
		}
	}
	for _, tid := range tenants {
		if !tenantctx.ValidTenantID(tid) {
			return nil, status.Error(codes.InvalidArgument, "malformed tenant id")
		}
	}
	if c.gateway && module == "" {
		// An old gateway: legacy rows only (never a module named "gateway").
		total := 0
		for _, tid := range tenants {
			n, err := s.Registry.Register(ctx, tid, "", c.id, defs)
			if err != nil {
				return nil, decisionError(err)
			}
			total += n
		}
		return &authv1.RegisterPermissionsResponse{Registered: uint32(total)}, nil
	}
	if module == "" {
		module = c.module
	}
	if s.Modules == nil {
		return nil, status.Error(codes.Unavailable, "registration unavailable")
	}
	reg := authz.Registration{Module: module, DisplayName: req.GetModuleDisplayName(), Registrant: c.id, Permissions: defs, DeclaresRoles: req.GetDeclaresRoles(),
		Grants: grants, Tenants: tenants}
	if c.gateway {
		reg.Delegate = "gateway"
	}
	for _, r := range req.GetRoles() {
		reg.Roles = append(reg.Roles, authz.ModuleRole{Slug: r.GetSlug(), DisplayName: r.GetDisplayName(), Description: r.GetDescription(), Permissions: r.GetPermissions()})
	}
	res, err := s.Modules.Register(ctx, reg)
	if err != nil {
		return nil, decisionError(err)
	}
	out := &authv1.RegisterPermissionsResponse{Registered: uint32(res.Registered), RolesUpserted: uint32(res.RolesUpserted), RolesRetired: res.RolesRetired}
	for _, sg := range res.Skipped {
		out.SkippedGrants = append(out.SkippedGrants, &authv1.SkippedGrant{Role: sg.Role, Tenants: uint32(sg.Tenants), SampleTenantIds: sg.Sample, Reason: sg.Reason})
		s.log().Warn("registration: built-in grant skipped", "module", module, "role", sg.Role, "tenants", sg.Tenants, "sample", sg.Sample, "reason", sg.Reason)
	}
	for _, re := range res.RoleErrors {
		out.RoleErrors = append(out.RoleErrors, &authv1.RoleError{Slug: re.Slug, Reason: re.Reason})
		s.log().Warn("registration: module role rejected", "module", module, "slug", re.Slug, "reason", re.Reason)
	}
	return out, nil
}

func (s *AuthorizationServer) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

// auditTenant picks the tenant of a refusal event: the platform tenant, or
// the first requested one.
func (s *AuthorizationServer) auditTenant(req *authv1.RegisterPermissionsRequest) string {
	if s.Modules != nil && s.Modules.PlatformTenant != "" {
		return s.Modules.PlatformTenant
	}
	for _, t := range req.GetTenantIds() {
		if tenantctx.ValidTenantID(t) {
			return t
		}
	}
	return ""
}

func (s *AuthorizationServer) emit(e audit.Event) {
	if s.Audit != nil && e.TenantID != "" {
		_ = s.Audit.Emit(e)
	}
}

func decisionError(err error) error {
	switch {
	case errors.Is(err, authz.ErrBadPermission), errors.Is(err, authz.ErrMalformed), errors.Is(err, authz.ErrBadRegistration):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, tenantctx.ErrCrossTenant), errors.Is(err, tenantctx.ErrNoActor), errors.Is(err, authz.ErrCrossTenant):
		return status.Error(codes.PermissionDenied, "cross_tenant_refused")
	}
	return status.Error(codes.Unavailable, "decision unavailable")
}
