package fuzz

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/token"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
)

func FuzzTokenParse(f *testing.F) {
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{5}, 32))
	ring := token.NewRing(token.NewMemKeys(), env, token.Config{})
	if err := ring.Load(f.Context()); err != nil {
		f.Fatal(err)
	}
	iss := token.NewIssuer(ring, "https://auth.example.org")
	good, _, _ := iss.Issue(token.Request{UserID: "u1", TenantID: "t1", SessionID: "s1"})
	parts := strings.Split(good, ".")
	f.Add(good)
	f.Add(parts[0] + "." + parts[1] + ".AAAA")
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add("")
	f.Add(strings.Repeat("a", 9000))
	f.Fuzz(func(t *testing.T, s string) {
		c, err := iss.Verify(s)
		if err == nil && s != good {
			// Only the genuine token may verify; anything else that passes is a forgery.
			if c.Subject != "u1" || c.SessionID != "s1" {
				t.Fatalf("forged token accepted: %q", s)
			}
		}
	})
}

func FuzzJWKS(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k := authclient.NewJWK("k1", pub, "active")
	f.Add([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"` + k.X + `","use":"sig","alg":"EdDSA"}]}`))
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"AAAA"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := authclient.ParseJWKS(data)
		if err != nil {
			return
		}
		for kid, key := range keys {
			if kid == "" || len(key) != ed25519.PublicKeySize {
				t.Fatalf("invalid key accepted: %q", kid)
			}
		}
	})
}
