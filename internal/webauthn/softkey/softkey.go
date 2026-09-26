// Package softkey is a software ES256 security key for tests (feature 018).
// It answers the JSON options the service sends to the browser with the JSON
// a browser returns from PublicKeyCredential.toJSON(): a "none" attestation
// for registration and a signed assertion for sign-in, built exactly as the
// WebAuthn Level 3 specification lays out authenticator data, so ceremonies
// run end to end through github.com/go-webauthn/webauthn without mocks. It is
// never wired into the service.
package softkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// Authenticator data flags (WebAuthn §6.1).
const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified
	flagBE = 0x08 // backup eligible
	flagBS = 0x10 // backup state
	flagAT = 0x40 // attested credential data included
)

// Key is one credential on a software authenticator. Exported fields steer
// negative tests.
type Key struct {
	// Origin is what the "browser" puts into clientDataJSON.
	Origin string
	// RPID overrides the relying party id taken from the options (a
	// phishing site hashing another id).
	RPID string
	// UserVerified sets the UV flag (a key PIN or biometric was used).
	UserVerified bool
	// NoPresence clears the UP flag (no touch).
	NoPresence bool
	// BackupEligible / BackupState set the BE / BS flags.
	BackupEligible, BackupState bool
	// Counter is the signature counter; Get increments it first unless
	// FreezeCounter is set (a clone replaying an old counter).
	Counter       uint32
	FreezeCounter bool
	// Transports reported at registration.
	Transports []string
	// Type overrides "webauthn.create" / "webauthn.get" in clientDataJSON.
	Type string

	ID     []byte
	AAGUID [16]byte
	priv   *ecdsa.PrivateKey
	handle []byte
}

// New creates a key with a random P-256 key pair and a 32-byte credential id.
func New(origin string) *Key {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	k := &Key{Origin: origin, ID: id, priv: priv, Transports: []string{"usb"}}
	copy(k.AAGUID[:], "softkey-aaguid-1")
	return k
}

var b64 = base64.RawURLEncoding

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	} `json:"publicKey"`
}

// Create answers credential creation options ({"publicKey": {...}}) with a
// registration response.
func (k *Key) Create(options []byte) ([]byte, error) {
	var o creationOptions
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, err
	}
	if o.PublicKey.Challenge == "" {
		return nil, errors.New("softkey: options without challenge")
	}
	k.handle, _ = b64.DecodeString(o.PublicKey.User.ID)
	cdj := k.clientData("webauthn.create", o.PublicKey.Challenge)
	pt, err := k.priv.PublicKey.Bytes() // 0x04 ‖ X ‖ Y
	if err != nil {
		return nil, err
	}
	// COSE_Key: kty EC2, alg ES256, crv P-256, x, y (RFC 9053).
	cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: pt[1:33], -3: pt[33:65]})
	if err != nil {
		return nil, err
	}
	ad := k.authData(o.PublicKey.RP.ID, flagAT)
	ad = append(ad, k.AAGUID[:]...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(k.ID))) // #nosec G115 -- test credential ids are short
	ad = append(ad, k.ID...)
	ad = append(ad, cose...)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.ID), "rawId": b64.EncodeToString(k.ID), "type": "public-key", "authenticatorAttachment": "cross-platform",
		"response":               map[string]any{"clientDataJSON": b64.EncodeToString(cdj), "attestationObject": b64.EncodeToString(att), "transports": k.Transports},
		"clientExtensionResults": map[string]any{},
	})
}

// Get answers credential request options with a signed assertion.
func (k *Key) Get(options []byte) ([]byte, error) {
	var o requestOptions
	if err := json.Unmarshal(options, &o); err != nil {
		return nil, err
	}
	if o.PublicKey.Challenge == "" {
		return nil, errors.New("softkey: options without challenge")
	}
	if !k.FreezeCounter {
		k.Counter++
	}
	cdj := k.clientData("webauthn.get", o.PublicKey.Challenge)
	ad := k.authData(o.PublicKey.RPID, 0)
	sum := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(k.ID), "rawId": b64.EncodeToString(k.ID), "type": "public-key", "authenticatorAttachment": "cross-platform",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cdj), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(k.handle)},
		"clientExtensionResults": map[string]any{},
	})
}

func (k *Key) clientData(typ, challenge string) []byte {
	if k.Type != "" {
		typ = k.Type
	}
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": k.Origin, "crossOrigin": false})
	return b
}

// authData is rpIdHash ‖ flags ‖ signCount (WebAuthn §6.1) with extra flags.
func (k *Key) authData(rpID string, extra byte) []byte {
	if k.RPID != "" {
		rpID = k.RPID
	}
	h := sha256.Sum256([]byte(rpID))
	flags := extra
	if !k.NoPresence {
		flags |= flagUP
	}
	if k.UserVerified {
		flags |= flagUV
	}
	if k.BackupEligible {
		flags |= flagBE
	}
	if k.BackupState {
		flags |= flagBS
	}
	out := append(h[:], flags)
	return binary.BigEndian.AppendUint32(out, k.Counter)
}
