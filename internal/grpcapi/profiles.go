package grpcapi

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/permref"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra-auth/v4/internal/user"
)

// ProfilesServer serves auth.v1.Profiles for platform services on the Freya
// channel: display name and avatar of users, never the phone number.
type ProfilesServer struct {
	authv1.UnimplementedProfilesServer
	Profiles *user.Profiles
}

// Lookup answers for at most 100 ids of one tenant; unknown ids are omitted.
func (s *ProfilesServer) Lookup(ctx context.Context, req *authv1.LookupProfilesRequest) (*authv1.LookupProfilesResponse, error) {
	ctx, svc := serviceCtx(ctx)
	actor, ok := tenantctx.FromContext(ctx)
	if !ok || svc == "" && actor.Kind != tenantctx.KindService {
		return nil, status.Error(codes.Unauthenticated, "service identity required")
	}
	if !tenantctx.ValidTenantID(req.GetTenantId()) || len(req.GetUserIds()) == 0 || len(req.GetUserIds()) > user.LookupMax {
		return nil, status.Error(codes.InvalidArgument, "malformed request")
	}
	// Services are tenant-agnostic callers: the lookup is scoped to the tenant named.
	actor.TenantID = req.GetTenantId()
	rows, err := s.Profiles.Lookup(ctx, actor, req.GetUserIds())
	if err != nil {
		return nil, status.Error(codes.Unavailable, "profiles unavailable")
	}
	out := &authv1.LookupProfilesResponse{}
	for _, r := range rows {
		out.Profiles = append(out.Profiles, &authv1.PublicProfile{UserId: r.ID, DisplayName: r.DisplayName, AvatarUrl: r.AvatarURL})
	}
	return out, nil
}

// ListMembers pages active member ids of one tenant (or filters user_ids).
func (s *ProfilesServer) ListMembers(ctx context.Context, req *authv1.ListMembersRequest) (*authv1.ListMembersResponse, error) {
	ctx, svc := serviceCtx(ctx)
	actor, ok := tenantctx.FromContext(ctx)
	if !ok || svc == "" && actor.Kind != tenantctx.KindService {
		return nil, status.Error(codes.Unauthenticated, "service identity required")
	}
	if !tenantctx.ValidTenantID(req.GetTenantId()) || req.GetLimit() < 0 || req.GetLimit() > user.MembersMax || len(req.GetUserIds()) > user.MembersMax {
		return nil, status.Error(codes.InvalidArgument, "malformed request")
	}
	actor.TenantID = req.GetTenantId()
	ids, next, err := s.Profiles.Members(ctx, actor, req.GetCursor(), int(req.GetLimit()), req.GetUserIds())
	if err != nil {
		return nil, status.Error(codes.Unavailable, "profiles unavailable")
	}
	return &authv1.ListMembersResponse{UserIds: ids, NextCursor: next}, nil
}

// Contacts returns the e-mail address of at most 100 active members of one
// tenant (feature 027; admitted by policy for the signing module only).
func (s *ProfilesServer) Contacts(ctx context.Context, req *authv1.LookupContactsRequest) (*authv1.LookupContactsResponse, error) {
	ctx, svc := serviceCtx(ctx)
	actor, ok := tenantctx.FromContext(ctx)
	if !ok || svc == "" && actor.Kind != tenantctx.KindService {
		return nil, status.Error(codes.Unauthenticated, "service identity required")
	}
	if !tenantctx.ValidTenantID(req.GetTenantId()) || len(req.GetUserIds()) == 0 || len(req.GetUserIds()) > user.LookupMax {
		return nil, status.Error(codes.InvalidArgument, "malformed request")
	}
	actor.TenantID = req.GetTenantId()
	rows, err := s.Profiles.Contacts(ctx, actor, req.GetUserIds(), svc)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "profiles unavailable")
	}
	out := &authv1.LookupContactsResponse{}
	for _, r := range rows {
		out.Contacts = append(out.Contacts, &authv1.Contact{UserId: r.ID, DisplayName: r.DisplayName, Email: r.Email})
	}
	return out, nil
}

// Members pages active members of one tenant with login, display name, the
// roles held in the calling module and group ids (admitted by policy for the
// teleport module only). The module is the caller's service name, derived
// from its SPIFFE id like RegisterPermissions; a caller naming no module is
// refused.
func (s *ProfilesServer) Members(ctx context.Context, req *authv1.ListMemberDetailsRequest) (*authv1.ListMemberDetailsResponse, error) {
	ctx, svc := serviceCtx(ctx)
	actor, ok := tenantctx.FromContext(ctx)
	if !ok || svc == "" && actor.Kind != tenantctx.KindService {
		return nil, status.Error(codes.Unauthenticated, "service identity required")
	}
	if svc == "" {
		svc = actor.ServiceID
	}
	module, err := permref.ModuleFromSPIFFE(svc)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "module service identity required")
	}
	if !tenantctx.ValidTenantID(req.GetTenantId()) || req.GetLimit() < 0 || req.GetLimit() > user.MembersMax || len(req.GetUserIds()) > user.MembersMax {
		return nil, status.Error(codes.InvalidArgument, "malformed request")
	}
	actor.TenantID = req.GetTenantId()
	rows, next, err := s.Profiles.MemberDetails(ctx, actor, module, svc, user.MemberDetailsQuery{
		After: req.GetCursor(), Limit: int(req.GetLimit()), IDs: req.GetUserIds(), Query: req.GetQuery()})
	switch {
	case errors.Is(err, user.ErrInvalidQuery):
		return nil, status.Error(codes.InvalidArgument, "malformed query")
	case err != nil:
		return nil, status.Error(codes.Unavailable, "profiles unavailable")
	}
	out := &authv1.ListMemberDetailsResponse{Members: make([]*authv1.MemberDetail, 0, len(rows)), NextCursor: next}
	for _, r := range rows {
		out.Members = append(out.Members, &authv1.MemberDetail{UserId: r.ID, Login: r.Login, DisplayName: r.DisplayName, Roles: r.Roles, GroupIds: r.GroupIDs})
	}
	return out, nil
}
