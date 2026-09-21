package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func valid(t *testing.T) Config {
	t.Helper()
	c := Default()
	c.ServiceName, c.TrustDomain = "auth", "example.org"
	c.Identity.Provider = "file"
	c.Identity.File.Cert, c.Identity.File.Key, c.Identity.File.Bundle = "c", "k", "b"
	c.Authz.Source, c.Authz.Path = "file", "p.yaml"
	c.Issuer = "https://auth.example.org"
	c.Edge.CertFile, c.Edge.KeyFile = "edge.pem", "edge.key"
	c.Edge.AllowedOrigins = []string{"https://auth.example.org"}
	c.DB.DSN = "postgres://auth_app:x@db:5432/auth?sslmode=verify-full"
	c.Valkey.Addresses = []string{"valkey:6379"}
	c.Valkey.Username, c.Valkey.Password = "auth", "secret"
	c.OpenFGA.URL = "https://openfga:8080"
	c.OpenFGA.PresharedKey = "k"
	kek := filepath.Join(t.TempDir(), "kek")
	_ = os.WriteFile(kek, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), 0o600)
	c.KEK.Source, c.KEK.Path = "file", kek
	c.Email.Host, c.Email.From = "smtp.example.org", "auth@example.org"
	return c
}

func TestDefaults(t *testing.T) {
	c := Default()
	if c.Edge.Addr != ":8443" || c.Edge.RateLimit.PerSecond != 20 || c.Email.Port != 465 || c.KEK.Source != "file" ||
		c.Token.AccessLifetime != 15*time.Minute || c.Token.RotationInterval != 24*time.Hour || c.Token.RetiringPeriod != 30*time.Minute ||
		c.Session.RevocationPoll != 5*time.Second || c.Valkey.AllowPlaintext || c.OpenFGA.AllowPlaintext || c.Email.AllowPlaintext ||
		c.Profile.AvatarMaxBytes != 2<<20 || c.Profile.AvatarMaxPixels != 4096*4096 || c.Profile.AvatarSize != 512 || c.Profile.AvatarDecodeConcurrency != 4 || c.Profile.LookupRatePerMinute != 120 {
		t.Fatalf("defaults %+v", c)
	}
}

func TestValidateAcceptsProductionShape(t *testing.T) {
	c := valid(t)
	c.Env = "production"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.Warnings()) != 0 {
		t.Fatalf("no warnings expected: %v", c.Warnings())
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"issuer https", func(c *Config) { c.Issuer = "http://auth.example.org" }, "issuer"},
		{"issuer path", func(c *Config) { c.Issuer = "https://auth.example.org/x" }, "issuer"},
		{"origin not https", func(c *Config) { c.Edge.AllowedOrigins = []string{"http://x"} }, "allowed_origins"},
		{"db dsn required", func(c *Config) { c.DB.DSN = "" }, "db.dsn"},
		{"avatar bytes bound", func(c *Config) { c.Profile.AvatarMaxBytes = 32 << 20 }, "avatar_max_bytes"},
		{"avatar pixels bound", func(c *Config) { c.Profile.AvatarMaxPixels = 0 }, "avatar_max_pixels"},
		{"avatar size bound", func(c *Config) { c.Profile.AvatarSize = 8 }, "avatar_size"},
		{"lookup rate positive", func(c *Config) { c.Profile.LookupRatePerMinute = 0 }, "lookup_rate_per_minute"},
		{"db sslmode weak in production", func(c *Config) { c.Env = "production"; c.DB.DSN = "postgres://u:p@db/auth?sslmode=require" }, "sslmode"},
		{"db sslmode disable in production", func(c *Config) { c.Env = "production"; c.DB.DSN = "postgres://u:p@db/auth?sslmode=disable" }, "sslmode"},
		{"valkey plaintext in production", func(c *Config) { c.Env = "production"; c.Valkey.AllowPlaintext = true }, "valkey.allow_plaintext"},
		{"valkey no address", func(c *Config) { c.Valkey.Addresses = nil }, "valkey.addresses"},
		{"openfga plaintext in production", func(c *Config) {
			c.Env = "production"
			c.OpenFGA.URL = "http://openfga:8080"
			c.OpenFGA.AllowPlaintext = true
		}, "openfga.allow_plaintext"},
		{"openfga http without opt-in", func(c *Config) { c.OpenFGA.URL = "http://openfga:8080" }, "openfga.url"},
		{"openfga key required", func(c *Config) { c.OpenFGA.PresharedKey = "" }, "openfga.preshared_key"},
		{"kek missing", func(c *Config) { c.KEK.Path = "/nonexistent" }, "kek"},
		{"kek env unknown", func(c *Config) { c.KEK.Source = "vault" }, "kek.source"},
		{"email plaintext in production", func(c *Config) { c.Env = "production"; c.Email.AllowPlaintext = true }, "email.allow_plaintext"},
		{"email from", func(c *Config) { c.Email.From = "" }, "email.from"},
		{"access lifetime >15m", func(c *Config) { c.Token.AccessLifetime = 16 * time.Minute }, "token.access_lifetime"},
		{"retiring shorter than access lifetime", func(c *Config) { c.Token.RetiringPeriod = 10 * time.Minute }, "token.retiring_period"},
		{"edge cert required in production", func(c *Config) { c.Env = "production"; c.Edge.CertFile = "" }, "edge.cert_file"},
		{"freya config invalid", func(c *Config) { c.ServiceName = "" }, "service_name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid(t)
			tc.mut(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestWarningsAndKEK(t *testing.T) {
	c := valid(t)
	c.Env = "dev"
	c.Edge.CertFile, c.Edge.KeyFile = "", ""
	c.Valkey.AllowPlaintext, c.OpenFGA.AllowPlaintext, c.Email.AllowPlaintext = true, true, true
	c.OpenFGA.URL = "http://openfga:8080"
	c.DB.DSN = "postgres://u:p@db/auth?sslmode=disable"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	w := strings.Join(c.Warnings(), "\n")
	for _, want := range []string{"edge", "valkey", "openfga", "email", "sslmode"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning for %s missing in %q", want, w)
		}
	}
	key, err := c.KEK.Load()
	if err != nil || len(key) != 32 {
		t.Fatalf("kek %d %v", len(key), err)
	}
	t.Setenv("AUTH_KEK", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	c.KEK.Source, c.KEK.Env = "env", "AUTH_KEK"
	if key, err := c.KEK.Load(); err != nil || len(key) != 32 {
		t.Fatalf("env kek %d %v", len(key), err)
	}
	c.KEK.Env = "AUTH_KEK_MISSING"
	if _, err := c.KEK.Load(); err == nil {
		t.Fatal("missing env must fail")
	}
	bad := filepath.Join(t.TempDir(), "kek")
	_ = os.WriteFile(bad, []byte("short"), 0o600)
	c.KEK.Source, c.KEK.Path = "file", bad
	if _, err := c.KEK.Load(); err == nil {
		t.Fatal("short kek must fail")
	}
}

func TestLoadYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte("service_name: auth\ntrust_domain: example.org\nissuer: https://a.example.org\ntoken:\n  access_lifetime: 10m\nedge:\n  addr: 127.0.0.1:0\n"), 0o600)
	c, err := Load(p)
	if err != nil || c.Token.AccessLifetime != 10*time.Minute || c.Edge.Addr != "127.0.0.1:0" || c.Issuer != "https://a.example.org" {
		t.Fatalf("%+v %v", c, err)
	}
	_ = os.WriteFile(p, []byte("unknown_field: 1\n"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("unknown field must fail")
	}
	if _, err := Load("/nonexistent.yaml"); err == nil {
		t.Fatal("missing file must fail")
	}
}
