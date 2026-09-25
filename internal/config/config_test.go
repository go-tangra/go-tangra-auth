package config

import (
	"os"
	"path/filepath"
	"slices"
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

func TestDirectoryDefaults(t *testing.T) {
	d := Default().Directory
	if !d.Enabled || d.AllowPlaintext || len(d.Targets.AllowCIDRs) != 0 ||
		!slices.Equal(d.Targets.AllowedPorts, []int{389, 636, 3268, 3269}) ||
		d.DialTimeout != 5*time.Second || d.MaxSizeLimit != 1000 || d.MaxTimeLimit != 60*time.Second ||
		d.RatePerMinute != 30 || d.MaxConnectionsPerTenant != 10 {
		t.Fatalf("directory defaults %+v", d)
	}
}

func TestDirectoryValidate(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Directory)
		want string
	}{
		{"deny cidr garbage", func(d *Directory) { d.Targets.DenyCIDRs = []string{"not-a-cidr"} }, "directory.targets.deny_cidrs"},
		{"deny cidr prefix too long", func(d *Directory) { d.Targets.DenyCIDRs = []string{"10.0.0.0/33"} }, "directory.targets.deny_cidrs"},
		{"allow cidr bare address", func(d *Directory) { d.Targets.AllowCIDRs = []string{"10.0.0.1"} }, "directory.targets.allow_cidrs"},
		{"allow cidr garbage after valid", func(d *Directory) { d.Targets.AllowCIDRs = []string{"10.0.0.0/8", "fd00::/129"} }, "directory.targets.allow_cidrs"},
		{"allow cidr empty string", func(d *Directory) { d.Targets.AllowCIDRs = []string{""} }, "directory.targets.allow_cidrs"},
		{"ports empty", func(d *Directory) { d.Targets.AllowedPorts = nil }, "directory.targets.allowed_ports"},
		{"port zero", func(d *Directory) { d.Targets.AllowedPorts = []int{389, 0} }, "directory.targets.allowed_ports"},
		{"port negative", func(d *Directory) { d.Targets.AllowedPorts = []int{-636} }, "directory.targets.allowed_ports"},
		{"port above 65535", func(d *Directory) { d.Targets.AllowedPorts = []int{65536} }, "directory.targets.allowed_ports"},
		{"dial timeout zero", func(d *Directory) { d.DialTimeout = 0 }, "directory.dial_timeout"},
		{"dial timeout above 30s", func(d *Directory) { d.DialTimeout = 31 * time.Second }, "directory.dial_timeout"},
		{"max size zero", func(d *Directory) { d.MaxSizeLimit = 0 }, "directory.max_size_limit"},
		{"max size above 1000", func(d *Directory) { d.MaxSizeLimit = 1001 }, "directory.max_size_limit"},
		{"max time below 1s", func(d *Directory) { d.MaxTimeLimit = 500 * time.Millisecond }, "directory.max_time_limit"},
		{"max time above 60s", func(d *Directory) { d.MaxTimeLimit = 61 * time.Second }, "directory.max_time_limit"},
		{"rate zero", func(d *Directory) { d.RatePerMinute = 0 }, "directory.rate_per_minute"},
		{"rate negative", func(d *Directory) { d.RatePerMinute = -1 }, "directory.rate_per_minute"},
		{"connections zero", func(d *Directory) { d.MaxConnectionsPerTenant = 0 }, "directory.max_connections_per_tenant"},
		{"connections negative", func(d *Directory) { d.MaxConnectionsPerTenant = -5 }, "directory.max_connections_per_tenant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid(t)
			tc.mut(&c.Directory)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestDirectoryValidateAcceptsBounds(t *testing.T) {
	c := valid(t)
	c.Env = "production"
	d := &c.Directory
	d.Targets.DenyCIDRs = []string{"10.0.0.0/8", "fd00::/8"}
	d.Targets.AllowCIDRs = []string{"10.89.0.0/24"}
	d.Targets.AllowedPorts = []int{1, 65535}
	d.DialTimeout, d.MaxTimeLimit = 30*time.Second, time.Second
	d.MaxSizeLimit, d.RatePerMinute, d.MaxConnectionsPerTenant = 1, 1, 1
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	d.MaxSizeLimit, d.MaxTimeLimit = 1000, 60*time.Second
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

// directory.allow_plaintext is an explicit operator opt-in in every
// environment (a directory without LDAPS/StartTLS); it is always warned.
func TestDirectoryPlaintextAcceptedWithWarning(t *testing.T) {
	for _, env := range []string{"dev", "production"} {
		c := valid(t)
		c.Env = env
		c.Directory.AllowPlaintext = true
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: allow_plaintext refused: %v", env, err)
		}
		if w := strings.Join(c.Warnings(), "\n"); !strings.Contains(w, "directory.allow_plaintext") {
			t.Fatalf("%s: no allow_plaintext warning in %q", env, w)
		}
	}
}

func TestDirectoryWarnings(t *testing.T) {
	c := valid(t)
	c.Env = "dev"
	c.Directory.AllowPlaintext = true
	c.Directory.Targets.AllowCIDRs = []string{"10.89.0.0/24", "fd00:89::/64"}
	w := strings.Join(c.Warnings(), "\n")
	for _, want := range []string{"directory", "allow_plaintext", "allow_cidrs", "10.89.0.0/24", "fd00:89::/64"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning for %s missing in %q", want, w)
		}
	}
	// deny_cidrs only narrows reach; it is not an insecure convenience.
	c = valid(t)
	c.Directory.Targets.DenyCIDRs = []string{"10.0.0.0/8"}
	for _, s := range c.Warnings() {
		if strings.Contains(s, "directory") {
			t.Fatalf("unexpected directory warning %q", s)
		}
	}
}

func TestDirectoryLoadYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte(`directory:
  enabled: false
  allow_plaintext: true
  targets:
    deny_cidrs: ["10.0.0.0/8"]
    allow_cidrs: ["10.89.0.0/24"]
    allowed_ports: [636]
  dial_timeout: 3s
  max_size_limit: 200
  max_time_limit: 20s
  rate_per_minute: 10
  max_connections_per_tenant: 4
`), 0o600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	d := c.Directory
	if d.Enabled || !d.AllowPlaintext || !slices.Equal(d.Targets.DenyCIDRs, []string{"10.0.0.0/8"}) ||
		!slices.Equal(d.Targets.AllowCIDRs, []string{"10.89.0.0/24"}) || !slices.Equal(d.Targets.AllowedPorts, []int{636}) ||
		d.DialTimeout != 3*time.Second || d.MaxSizeLimit != 200 || d.MaxTimeLimit != 20*time.Second ||
		d.RatePerMinute != 10 || d.MaxConnectionsPerTenant != 4 {
		t.Fatalf("directory %+v", d)
	}
}
