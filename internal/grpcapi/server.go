package grpcapi

import (
	"google.golang.org/grpc"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
)

// Handlers are the auth.v1 service implementations; nil entries register the
// generated Unimplemented stubs so every method exists (and is policed) from
// the first start.
type Handlers struct {
	Keys          authv1.KeysServer
	Sessions      authv1.SessionsServer
	Authorization authv1.AuthorizationServer
	Profiles      authv1.ProfilesServer
	Enrollment    authv1.EnrollmentServer
}

// Register mounts the auth.v1 services on a Freya gRPC server (or any registrar).
func Register(s grpc.ServiceRegistrar, h Handlers) {
	if h.Keys == nil {
		h.Keys = authv1.UnimplementedKeysServer{}
	}
	if h.Sessions == nil {
		h.Sessions = authv1.UnimplementedSessionsServer{}
	}
	if h.Authorization == nil {
		h.Authorization = authv1.UnimplementedAuthorizationServer{}
	}
	authv1.RegisterKeysServer(s, h.Keys)
	authv1.RegisterSessionsServer(s, h.Sessions)
	if h.Profiles == nil {
		h.Profiles = authv1.UnimplementedProfilesServer{}
	}
	if h.Enrollment == nil {
		h.Enrollment = authv1.UnimplementedEnrollmentServer{}
	}
	authv1.RegisterAuthorizationServer(s, h.Authorization)
	authv1.RegisterProfilesServer(s, h.Profiles)
	authv1.RegisterEnrollmentServer(s, h.Enrollment)
}
