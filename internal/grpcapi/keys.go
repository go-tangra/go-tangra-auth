package grpcapi

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/v4/internal/token"
)

// KeysServer serves auth.v1.Keys from the ring.
type KeysServer struct {
	authv1.UnimplementedKeysServer
	Ring *token.Ring
	// TokenLifetime + skew bound how long a retired key can still matter.
	NotAfterGrace func() (lifetime, skew int64)
}

// List returns every key in a verifiable state.
func (s *KeysServer) List(context.Context, *authv1.ListKeysRequest) (*authv1.ListKeysResponse, error) {
	out := &authv1.ListKeysResponse{}
	for _, k := range s.Ring.Keys() {
		key := &authv1.Key{Kid: k.KID, Kty: "OKP", Crv: "Ed25519", PublicKey: append([]byte(nil), k.PublicKey...), State: k.State}
		if k.RetiredAt != nil && s.NotAfterGrace != nil {
			life, skew := s.NotAfterGrace()
			key.NotAfter = timestamppb.New(k.RetiredAt.Add(secs(life + skew)))
		}
		out.Keys = append(out.Keys, key)
	}
	return out, nil
}
