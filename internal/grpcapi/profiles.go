package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
	"github.com/go-freya/freya/services/auth/internal/user"
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
