package authclient

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/go-kratos/kratos/v3/middleware"
	ktransport "github.com/go-kratos/kratos/v3/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
)

// GRPCKeys fetches keys over the Freya channel (auth.v1.Keys/List).
type GRPCKeys struct{ Client authv1.KeysClient }

func (g GRPCKeys) Keys(ctx context.Context) (map[string]ed25519.PublicKey, error) {
	resp, err := g.Client.List(ctx, &authv1.ListKeysRequest{})
	if err != nil {
		return nil, err
	}
	out := make(map[string]ed25519.PublicKey, len(resp.GetKeys()))
	for _, k := range resp.GetKeys() {
		if k.GetKty() != "OKP" || k.GetCrv() != "Ed25519" || len(k.GetPublicKey()) != ed25519.PublicKeySize || k.GetKid() == "" {
			return nil, fmt.Errorf("authclient: unsupported key %q", k.GetKid())
		}
		if _, dup := out[k.GetKid()]; dup {
			return nil, fmt.Errorf("authclient: duplicate kid %q", k.GetKid())
		}
		out[k.GetKid()] = ed25519.PublicKey(append([]byte(nil), k.GetPublicKey()...))
	}
	return out, nil
}

// GRPCRevocations pages auth.v1.Sessions/RevokedSince.
type GRPCRevocations struct {
	Client authv1.SessionsClient
	Limit  uint32
}

func (g GRPCRevocations) Since(ctx context.Context, cursor string) ([]Revocation, string, error) {
	resp, err := g.Client.RevokedSince(ctx, &authv1.RevokedSinceRequest{Cursor: cursor, Limit: g.Limit})
	if err != nil {
		return nil, cursor, err
	}
	out := make([]Revocation, 0, len(resp.GetRevocations()))
	for _, r := range resp.GetRevocations() {
		out = append(out, Revocation{TS: r.GetTs().AsTime(), Kind: r.GetKind(), SubjectID: r.GetSubjectId(), TenantID: r.GetTenantId(), Reason: r.GetReason()})
	}
	return out, resp.GetNextCursor(), nil
}

// KratosMiddleware requires a valid end-user token on every call of a Freya
// (Kratos) server; the peer service was already authenticated by the channel.
func KratosMiddleware(v *Verifier) middleware.Middleware {
	return func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			tok := ""
			if tr, ok := ktransport.FromServerContext(ctx); ok {
				tok = BearerToken(tr.RequestHeader().Get("authorization"))
			}
			id, err := v.Verify(ctx, tok)
			if err != nil {
				return nil, status.Error(codes.Unauthenticated, "unauthenticated")
			}
			return next(WithIdentity(ctx, id), req)
		}
	}
}
