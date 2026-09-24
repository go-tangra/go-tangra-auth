package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
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
}

// builtinRoles may receive grants from registrants.
var builtinRoles = map[string]bool{"owner": true, "admin": true, "member": true, "auditor": true, "operator": true}

func serviceCtx(ctx context.Context) (context.Context, string) {
	p, ok := authn.FromContext(ctx)
	if !ok {
		return ctx, ""
	}
	return tenantctx.WithActor(ctx, tenantctx.ActorFromService(p)), p.ID.String()
}

func (s *AuthorizationServer) Check(ctx context.Context, req *authv1.CheckRequest) (*authv1.CheckResponse, error) {
	ctx, _ = serviceCtx(ctx)
	ref, err := authz.ParsePermissionRef(req.GetResource() + ":" + req.GetAction())
	if err != nil || !tenantctx.ValidTenantID(req.GetTenantId()) || req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "malformed request")
	}
	d, err := s.Decider.Decide(ctx, req.GetTenantId(), req.GetUserId(), ref)
	if err != nil {
		return nil, decisionError(err)
	}
	return &authv1.CheckResponse{Allowed: d.Allowed, Reason: d.Reason, PolicyVersion: d.PolicyVersion}, nil
}

func (s *AuthorizationServer) BatchCheck(ctx context.Context, req *authv1.BatchCheckRequest) (*authv1.BatchCheckResponse, error) {
	ctx, _ = serviceCtx(ctx)
	if !tenantctx.ValidTenantID(req.GetTenantId()) || req.GetUserId() == "" || len(req.GetPermissions()) == 0 || len(req.GetPermissions()) > 100 {
		return nil, status.Error(codes.InvalidArgument, "malformed request")
	}
	refs := make([]authz.PermissionRef, 0, len(req.GetPermissions()))
	for _, p := range req.GetPermissions() {
		ref, err := authz.ParsePermissionRef(p.GetResource() + ":" + p.GetAction())
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "malformed permission")
		}
		refs = append(refs, ref)
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

func (s *AuthorizationServer) RegisterPermissions(ctx context.Context, req *authv1.RegisterPermissionsRequest) (*authv1.RegisterPermissionsResponse, error) {
	ctx, registrant := serviceCtx(ctx)
	if registrant == "" {
		return nil, status.Error(codes.Unauthenticated, "service identity required")
	}
	defs := make([]authz.Permission, 0, len(req.GetPermissions()))
	for _, p := range req.GetPermissions() {
		defs = append(defs, authz.Permission{Resource: p.GetResource(), Action: p.GetAction(), Description: p.GetDescription()})
	}
	// Grants may only name the registrant's own permissions from this request.
	own := map[string]bool{}
	for _, d := range defs {
		own[d.Resource+":"+d.Action] = true
	}
	for _, g := range req.GetBuiltinGrants() {
		if s.Roles == nil || !builtinRoles[g.GetRole()] {
			return nil, status.Error(codes.InvalidArgument, "builtin_grants: unknown role")
		}
		for _, p := range g.GetPermissions() {
			if !own[p] {
				return nil, status.Error(codes.InvalidArgument, "builtin_grants: permission not registered by this request")
			}
		}
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
	total := 0
	for _, tid := range tenants {
		if !tenantctx.ValidTenantID(tid) {
			return nil, status.Error(codes.InvalidArgument, "malformed tenant id")
		}
		n, err := s.Registry.Register(ctx, tid, registrant, defs)
		if err != nil {
			return nil, decisionError(err)
		}
		total += n
		for _, g := range req.GetBuiltinGrants() {
			if err := s.Roles.GrantBuiltin(ctx, tid, g.GetRole(), g.GetPermissions()); err != nil {
				return nil, decisionError(err)
			}
		}
	}
	return &authv1.RegisterPermissionsResponse{Registered: uint32(total)}, nil
}

func decisionError(err error) error {
	switch err {
	case authz.ErrBadPermission, authz.ErrMalformed:
		return status.Error(codes.InvalidArgument, err.Error())
	case tenantctx.ErrCrossTenant, tenantctx.ErrNoActor, authz.ErrCrossTenant:
		return status.Error(codes.PermissionDenied, "cross_tenant_refused")
	}
	return status.Error(codes.Unavailable, "decision unavailable")
}
