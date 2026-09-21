package authclient

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type identityKey struct{}

// WithIdentity attaches a verified identity.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// FromContext returns the identity attached by the middleware.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// BearerToken extracts a bearer credential ("" when absent).
func BearerToken(authorization string) string {
	if len(authorization) > 7 && strings.EqualFold(authorization[:7], "Bearer ") {
		return strings.TrimSpace(authorization[7:])
	}
	return ""
}

// UnaryInterceptor requires a valid end-user token on every RPC (the Freya
// channel already authenticated the calling service; this authenticates the
// user it acts for).
func UnaryInterceptor(v *Verifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		tok := ""
		if vals := md.Get("authorization"); len(vals) > 0 {
			tok = BearerToken(vals[0])
		}
		id, err := v.Verify(ctx, tok)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}
		return next(WithIdentity(ctx, id), req)
	}
}

// Middleware requires a valid bearer token on every HTTP request.
func Middleware(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := v.Verify(r.Context(), BearerToken(r.Header.Get("Authorization")))
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("WWW-Authenticate", `Bearer realm="freya"`)
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"reason":"unauthenticated"}`))
				return
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
		})
	}
}
