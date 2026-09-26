package fuzz

import (
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/webauthn"
	"github.com/go-tangra/go-tangra-auth/v4/internal/webauthn/softkey"
)

// Feature 018 (SR-003): the browser's authenticator responses are parsed
// through size-bounded wrappers. Arbitrary input must never panic, and
// anything over the bound is refused before parsing.

const waOrigin = "https://auth.example.org"

var (
	waCreation = []byte(`{"publicKey":{"challenge":"c2VlZC1jaGFsbGVuZ2UtMTIzNDU2","rp":{"id":"auth.example.org"},"user":{"id":"dXNlcg"}}}`)
	waRequest  = []byte(`{"publicKey":{"challenge":"c2VlZC1jaGFsbGVuZ2UtMTIzNDU2","rpId":"auth.example.org"}}`)
)

func FuzzWebAuthnCreation(f *testing.F) {
	k := softkey.New(waOrigin)
	if seed, err := k.Create(waCreation); err == nil {
		f.Add(seed)
	}
	for _, s := range []string{"", "{}", `{"id":"AA","rawId":"AA","type":"public-key","response":{}}`, `{"response":{"attestationObject":"oA"}}`, "\xff"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := webauthn.ParseCreation(b)
		if err == nil && p == nil {
			t.Fatal("nil result without error")
		}
		if len(b) > webauthn.MaxResponseBytes && err == nil {
			t.Fatal("oversized response parsed")
		}
	})
}

func FuzzWebAuthnAssertion(f *testing.F) {
	k := softkey.New(waOrigin)
	if seed, err := k.Get(waRequest); err == nil {
		f.Add(seed)
	}
	for _, s := range []string{"", "{}", `{"id":"AA","rawId":"AA","type":"public-key","response":{"authenticatorData":"AA"}}`, "[]", "\x00"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := webauthn.ParseAssertion(b)
		if err == nil && p == nil {
			t.Fatal("nil result without error")
		}
		if len(b) > webauthn.MaxResponseBytes && err == nil {
			t.Fatal("oversized response parsed")
		}
	})
}
