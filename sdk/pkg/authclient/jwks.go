package authclient

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// JWK is an Ed25519 verification key (RFC 8037) with the service's key state.
type JWK struct {
	Kty   string `json:"kty"`
	Crv   string `json:"crv"`
	Kid   string `json:"kid"`
	X     string `json:"x"`
	Use   string `json:"use"`
	Alg   string `json:"alg"`
	State string `json:"freya_state,omitempty"` // active | retiring | retired
}

// JWKS is the published key set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewJWK renders an Ed25519 public key.
func NewJWK(kid string, pub ed25519.PublicKey, state string) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", Kid: kid, X: base64.RawURLEncoding.EncodeToString(pub), Use: "sig", Alg: "EdDSA", State: state}
}

// PublicKey decodes the key, refusing anything that is not Ed25519/EdDSA.
func (k JWK) PublicKey() (ed25519.PublicKey, error) {
	if k.Kty != "OKP" || k.Crv != "Ed25519" || (k.Alg != "" && k.Alg != "EdDSA") || k.Kid == "" {
		return nil, fmt.Errorf("authclient: unsupported key %q", k.Kid)
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("authclient: malformed key %q", k.Kid)
	}
	return ed25519.PublicKey(raw), nil
}

// ParseJWKS decodes a key set into kid → key. One bad key fails the whole
// set so a poisoned document is never partially trusted.
func ParseJWKS(data []byte) (map[string]ed25519.PublicKey, error) {
	if len(data) > 64<<10 {
		return nil, errors.New("authclient: jwks too large")
	}
	var set JWKS
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("authclient: jwks: %w", err)
	}
	out := make(map[string]ed25519.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		pub, err := k.PublicKey()
		if err != nil {
			return nil, err
		}
		if _, dup := out[k.Kid]; dup {
			return nil, fmt.Errorf("authclient: duplicate kid %q", k.Kid)
		}
		out[k.Kid] = pub
	}
	return out, nil
}
