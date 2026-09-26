package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Feature 018: the relying party is derived from the issuer unless the
// webauthn block overrides it.
func TestWebAuthnDefaultsFromIssuer(t *testing.T) {
	d := Default().WebAuthn
	if d.Enabled != nil || d.RPID != "" || len(d.Origins) != 0 || d.DisplayName != "" || d.UserVerification != "preferred" || d.TimeoutSeconds != 300 {
		t.Fatalf("webauthn defaults %+v", d)
	}
	for _, tc := range []struct{ issuer, rpID, origin string }{
		{"https://auth.example.org", "auth.example.org", "https://auth.example.org"},
		{"https://portal.infra.verax.net:8443", "portal.infra.verax.net", "https://portal.infra.verax.net:8443"},
		{"https://portal.infra.verax.net:443/", "portal.infra.verax.net", "https://portal.infra.verax.net"},
		{"https://localhost:8443", "localhost", "https://localhost:8443"},
	} {
		c := valid(t)
		c.Issuer = tc.issuer
		c.Edge.AllowedOrigins = nil
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: %v", tc.issuer, err)
		}
		rp := c.RelyingParty()
		if !rp.Enabled || rp.ID != tc.rpID || !slices.Equal(rp.Origins, []string{tc.origin}) || rp.DisplayName != "Tangra" ||
			rp.UserVerification != "preferred" || rp.Timeout != 5*time.Minute {
			t.Fatalf("%s: %+v", tc.issuer, rp)
		}
	}
}

func TestWebAuthnOverrides(t *testing.T) {
	c := valid(t)
	c.Env = "production"
	c.Issuer = "https://portal.infra.verax.net:8443"
	c.MFA.Issuer = "Acme"
	c.WebAuthn = WebAuthn{RPID: "infra.verax.net", Origins: []string{"https://portal.infra.verax.net:8443", "https://login.infra.verax.net"},
		UserVerification: "required", TimeoutSeconds: 60}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	rp := c.RelyingParty()
	if rp.ID != "infra.verax.net" || len(rp.Origins) != 2 || rp.DisplayName != "Acme" || rp.UserVerification != "required" || rp.Timeout != time.Minute {
		t.Fatalf("%+v", rp)
	}
	c.WebAuthn.DisplayName = "Verax"
	if rp := c.RelyingParty(); rp.DisplayName != "Verax" {
		t.Fatalf("display name %q", rp.DisplayName)
	}
	// Development may use a plain-http localhost origin.
	c.Env = "dev"
	c.Issuer = "https://localhost:8443"
	c.WebAuthn = WebAuthn{Origins: []string{"https://localhost:8443", "http://localhost:5173"}, UserVerification: "preferred", TimeoutSeconds: 30}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.WebAuthn.TimeoutSeconds = 600
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWebAuthnRejects(t *testing.T) {
	off := false
	cases := []struct {
		name string
		env  string
		mut  func(*Config)
		want string
	}{
		{"rp id not a parent of the origin host", "dev", func(c *Config) { c.WebAuthn.RPID = "other.example.org" }, "webauthn.rp_id"},
		{"rp id suffix without a dot boundary", "dev", func(c *Config) {
			c.WebAuthn.RPID = "example.org"
			c.WebAuthn.Origins = []string{"https://authexample.org"}
		}, "webauthn.rp_id"},
		{"rp id a bare public suffix", "dev", func(c *Config) { c.WebAuthn.RPID = "org" }, "webauthn.rp_id"},
		{"rp id an ip address", "dev", func(c *Config) { c.WebAuthn.RPID = "10.0.0.1"; c.WebAuthn.Origins = []string{"https://10.0.0.1"} }, "webauthn.rp_id"},
		{"rp id with a port", "dev", func(c *Config) { c.WebAuthn.RPID = "auth.example.org:443" }, "webauthn.rp_id"},
		{"origin with a path", "dev", func(c *Config) { c.WebAuthn.Origins = []string{"https://auth.example.org/console"} }, "webauthn.origins"},
		{"origin unparsable", "dev", func(c *Config) { c.WebAuthn.Origins = []string{"https://%zz"} }, "webauthn.origins"},
		{"origin plain http outside localhost", "dev", func(c *Config) { c.WebAuthn.Origins = []string{"http://auth.example.org"} }, "webauthn.origins"},
		{"origin plain http localhost in production", "production", func(c *Config) {
			c.WebAuthn.RPID = "localhost"
			c.WebAuthn.Origins = []string{"http://localhost:5173"}
		}, "webauthn.origins"},
		{"user verification unknown", "dev", func(c *Config) { c.WebAuthn.UserVerification = "discouraged" }, "webauthn.user_verification"},
		{"timeout below 30s", "dev", func(c *Config) { c.WebAuthn.TimeoutSeconds = 29 }, "webauthn.timeout_seconds"},
		{"timeout above 600s", "dev", func(c *Config) { c.WebAuthn.TimeoutSeconds = 601 }, "webauthn.timeout_seconds"},
		{"display name too long", "dev", func(c *Config) { c.WebAuthn.DisplayName = strings.Repeat("x", 65) }, "webauthn.display_name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid(t)
			c.Env = tc.env
			tc.mut(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want mention of %q", err, tc.want)
			}
		})
	}
	// Disabled: the relying party is not validated (nothing uses it).
	c := valid(t)
	c.WebAuthn = WebAuthn{Enabled: &off, RPID: "other.example.org", UserVerification: "preferred", TimeoutSeconds: 300}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

// An issuer reached by IP address cannot be a relying party (browsers refuse
// IP RP IDs): keys are off by default and the start-up warning says why. An
// explicit enabled: true is refused.
func TestWebAuthnIssuerIPAndDisabled(t *testing.T) {
	c := valid(t)
	c.Env = "dev"
	c.Issuer = "https://10.0.0.5:8443"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if rp := c.RelyingParty(); rp.Enabled {
		t.Fatalf("ip issuer must disable keys: %+v", rp)
	}
	if w := strings.Join(c.Warnings(), "\n"); !strings.Contains(w, "webauthn") || !strings.Contains(w, "10.0.0.5") {
		t.Fatalf("warnings %q", w)
	}
	on := true
	c.WebAuthn.Enabled = &on
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "webauthn.rp_id") {
		t.Fatalf("explicitly enabled on an ip issuer: %v", err)
	}
	off := false
	c = valid(t)
	c.WebAuthn.Enabled = &off
	if rp := c.RelyingParty(); rp.Enabled {
		t.Fatal("explicitly disabled")
	}
	if w := strings.Join(c.Warnings(), "\n"); !strings.Contains(w, "webauthn.enabled is false") {
		t.Fatalf("warnings %q", w)
	}
}

func TestWebAuthnLoadYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte(`webauthn:
  enabled: true
  rp_id: example.org
  origins: ["https://auth.example.org"]
  display_name: Acme
  user_verification: required
  timeout_seconds: 120
`), 0o600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	w := c.WebAuthn
	if w.Enabled == nil || !*w.Enabled || w.RPID != "example.org" || !slices.Equal(w.Origins, []string{"https://auth.example.org"}) ||
		w.DisplayName != "Acme" || w.UserVerification != "required" || w.TimeoutSeconds != 120 {
		t.Fatalf("webauthn %+v", w)
	}
	_ = os.WriteFile(p, []byte("webauthn:\n  attestation: direct\n"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("unknown webauthn key must fail (strict decoding)")
	}
}
