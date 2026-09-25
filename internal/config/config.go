package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	fconfig "github.com/go-tangra/go-tangra/v4/config"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
	"gopkg.in/yaml.v3"
)

// Config is the auth service configuration: the Freya service config plus the
// service's own sections. Validate MUST pass before the service starts.
type Config struct {
	fconfig.Config `yaml:",inline"`
	// Issuer is the public base URL (https, no path) placed in tokens' `iss`.
	Issuer  string  `yaml:"issuer"`
	Edge    Edge    `yaml:"edge"`
	DB      DB      `yaml:"db"`
	Valkey  Valkey  `yaml:"valkey"`
	OpenFGA OpenFGA `yaml:"openfga"`
	KEK     KEK     `yaml:"kek"`
	Email   Email   `yaml:"email"`
	Token   Token   `yaml:"token"`
	Session Session `yaml:"session"`
	Gateway Gateway `yaml:"gateway"`
	Profile Profile `yaml:"profile"`
	// Directory bounds the LDAP directory import (feature 016).
	Directory Directory `yaml:"directory"`
}

// Directory configures outbound LDAP connections used for directory import
// (research D5, D15). Validated even when disabled.
type Directory struct {
	Enabled                 bool             `yaml:"enabled"`         // false removes the routes and the nav entry
	AllowPlaintext          bool             `yaml:"allow_plaintext"` // ldap:// without StartTLS: bind password in clear text; warned at start
	Targets                 DirectoryTargets `yaml:"targets"`
	DialTimeout             time.Duration    `yaml:"dial_timeout"`               // (0, 30s], default 5s
	MaxSizeLimit            int              `yaml:"max_size_limit"`             // [1, 1000] entries per search
	MaxTimeLimit            time.Duration    `yaml:"max_time_limit"`             // [1s, 60s] per search
	RatePerMinute           int              `yaml:"rate_per_minute"`            // per-tenant test/search rate (default 30)
	MaxConnectionsPerTenant int              `yaml:"max_connections_per_tenant"` // default 10
}

// DirectoryTargets is the dial-time address policy. The always-denied set
// (loopback, link-local incl. cloud metadata, unspecified, multicast) is
// enforced in code and cannot be overridden here.
type DirectoryTargets struct {
	DenyCIDRs    []string `yaml:"deny_cidrs"`    // platform-internal networks, operator-extensible
	AllowCIDRs   []string `yaml:"allow_cidrs"`   // overrides deny_cidrs only
	AllowedPorts []int    `yaml:"allowed_ports"` // default 389, 636, 3268, 3269
}

// Gateway enables gateway mode: the browser API and console are served on the
// Freya HTTP server (mTLS, gateway only), the edge listener is not started,
// CSRF and security headers are delegated to the gateway, and the module
// registers its manifest with the gateway service.
type Gateway struct {
	Enabled bool   `yaml:"enabled"`
	Service string `yaml:"service"` // discovery name of the gateway (default "gateway")
}

// Profile bounds the avatar pipeline and the profile lookup (feature 004).
type Profile struct {
	AvatarMaxBytes          int64 `yaml:"avatar_max_bytes"`          // upload body limit (default 2 MiB)
	AvatarMaxPixels         int64 `yaml:"avatar_max_pixels"`         // width×height gate before decoding (default 4096²)
	AvatarSize              int   `yaml:"avatar_size"`               // stored square edge in pixels (default 512)
	AvatarDecodeConcurrency int   `yaml:"avatar_decode_concurrency"` // concurrent decodes per instance (default 4)
	LookupRatePerMinute     int   `yaml:"lookup_rate_per_minute"`    // per-user rate for /api/v1/users lookups (default 120)
}

// Edge configures the browser-facing listener.
type Edge struct {
	Addr           string         `yaml:"addr"`
	CertFile       string         `yaml:"cert_file"`
	KeyFile        string         `yaml:"key_file"`
	AllowedOrigins []string       `yaml:"allowed_origins"`
	TrustedProxies []string       `yaml:"trusted_proxies"`
	RateLimit      edge.RateLimit `yaml:"rate_limit"`
}

// DB configures TimescaleDB access.
type DB struct {
	DSN        string `yaml:"dsn"`         // application role (no BYPASSRLS)
	MigrateDSN string `yaml:"migrate_dsn"` // migration role; empty = DSN
	MaxConns   int32  `yaml:"max_conns"`
}

// Valkey configures the cache.
type Valkey struct {
	Addresses      []string `yaml:"addresses"`
	Username       string   `yaml:"username"`
	Password       string   `yaml:"password"`
	AllowPlaintext bool     `yaml:"allow_plaintext"`
	CAFile         string   `yaml:"ca_file"` // optional private CA for TLS
}

// OpenFGA configures the authorization engine.
type OpenFGA struct {
	URL            string `yaml:"url"`
	PresharedKey   string `yaml:"preshared_key"`
	StoreID        string `yaml:"store_id"` // empty = bootstrap/create on start
	AllowPlaintext bool   `yaml:"allow_plaintext"`
}

// KEK locates the key-encryption key (32 bytes, base64) used for envelope encryption.
type KEK struct {
	Source string `yaml:"source"` // file | env
	Path   string `yaml:"path"`
	Env    string `yaml:"env"`
}

// Email configures delivery. Mail is rendered and sent by notification
// (feature 017); auth holds no relay. The relay keys below are what auth ≤ 4.1
// used: they still load so existing files keep working, are ignored, and are
// named in one start-up warning.
type Email struct {
	Transport      string `yaml:"transport"` // notification (default) | log (development only); smtp = notification
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	From           string `yaml:"from"`
	AllowPlaintext bool   `yaml:"allow_plaintext"`
}

// Mode is the effective transport: "notification" or "log".
func (e Email) Mode() string {
	if e.Transport == "log" {
		return "log"
	}
	return "notification"
}

// ignored lists the relay keys that are set (names only, never values).
func (e Email) ignored() []string {
	var keys []string
	if e.Transport == "smtp" {
		keys = append(keys, "transport smtp")
	}
	for _, k := range []struct {
		name string
		set  bool
	}{{"host", e.Host != ""}, {"port", e.Port != 0}, {"username", e.Username != ""}, {"password", e.Password != ""}, {"from", e.From != ""}, {"allow_plaintext", e.AllowPlaintext}} {
		if k.set {
			keys = append(keys, k.name)
		}
	}
	return keys
}

// Token configures proofs of identity and key rotation.
type Token struct {
	AccessLifetime   time.Duration `yaml:"access_lifetime"`
	RotationInterval time.Duration `yaml:"rotation_interval"`
	RetiringPeriod   time.Duration `yaml:"retiring_period"`
	ClockSkew        time.Duration `yaml:"clock_skew"`
}

// Session configures session defaults used when a tenant policy is silent.
type Session struct {
	RevocationPoll time.Duration `yaml:"revocation_poll"`
}

// Default returns secure defaults on top of the Freya defaults.
func Default() Config {
	return Config{
		Config:  fconfig.Default(),
		Edge:    Edge{Addr: ":8443", RateLimit: edge.RateLimit{PerSecond: 20, Burst: 40, Routes: map[string]edge.RateLimit{"/api/v1/signin": {PerSecond: 2, Burst: 5}, "/api/v1/recovery": {PerSecond: 1, Burst: 3}}}},
		DB:      DB{MaxConns: 16},
		KEK:     KEK{Source: "file"},
		Email:   Email{Transport: "notification"},
		Token:   Token{AccessLifetime: 15 * time.Minute, RotationInterval: 24 * time.Hour, RetiringPeriod: 30 * time.Minute, ClockSkew: 60 * time.Second},
		Session: Session{RevocationPoll: 5 * time.Second},
		Gateway: Gateway{Service: "gateway"},
		Profile: Profile{AvatarMaxBytes: 2 << 20, AvatarMaxPixels: 4096 * 4096, AvatarSize: 512, AvatarDecodeConcurrency: 4, LookupRatePerMinute: 120},
		Directory: Directory{
			Enabled:                 true,
			Targets:                 DirectoryTargets{AllowedPorts: []int{389, 636, 3268, 3269}},
			DialTimeout:             5 * time.Second,
			MaxSizeLimit:            1000,
			MaxTimeLimit:            60 * time.Second,
			RatePerMinute:           30,
			MaxConnectionsPerTenant: 10,
		},
	}
}

// Load reads YAML over Default(); unknown fields are rejected. Not yet validated.
func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the Freya config and every service section.
func (c Config) Validate() error {
	if err := c.Config.Validate(); err != nil {
		return err
	}
	prod := c.IsProduction()
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return errors.New("config: issuer must be an https origin without path")
	}
	for _, o := range c.Edge.AllowedOrigins {
		if !strings.HasPrefix(o, "https://") {
			return errors.New("config: edge.allowed_origins must be https origins")
		}
	}
	if c.Gateway.Enabled {
		if c.Server.HTTPAddr == "" {
			return errors.New("config: gateway mode requires server.http_addr (the gateway forwards to the Freya HTTP server)")
		}
		if c.Gateway.Service == "" {
			return errors.New("config: gateway.service is required in gateway mode")
		}
	} else if prod && (c.Edge.CertFile == "" || c.Edge.KeyFile == "") {
		return errors.New("config: edge.cert_file and edge.key_file are required in production")
	}
	if c.Profile.AvatarMaxBytes <= 0 || c.Profile.AvatarMaxBytes > 16<<20 {
		return errors.New("config: profile.avatar_max_bytes must be within (0, 16 MiB]")
	}
	if c.Profile.AvatarMaxPixels <= 0 || c.Profile.AvatarMaxPixels > 64_000_000 {
		return errors.New("config: profile.avatar_max_pixels must be within (0, 64M]")
	}
	if c.Profile.AvatarSize < 32 || c.Profile.AvatarSize > 1024 {
		return errors.New("config: profile.avatar_size must be within [32, 1024]")
	}
	if c.Profile.AvatarDecodeConcurrency <= 0 || c.Profile.LookupRatePerMinute <= 0 {
		return errors.New("config: profile.avatar_decode_concurrency and profile.lookup_rate_per_minute must be positive")
	}
	if c.DB.DSN == "" {
		return errors.New("config: db.dsn is required")
	}
	if prod && !strings.Contains(c.DB.DSN, "sslmode=verify-full") && !strings.Contains(c.DB.DSN, "sslmode=verify-ca") {
		return errors.New("config: db.dsn must use sslmode=verify-full (or verify-ca) in production")
	}
	if len(c.Valkey.Addresses) == 0 {
		return errors.New("config: valkey.addresses is required")
	}
	if prod && c.Valkey.AllowPlaintext {
		return errors.New("config: valkey.allow_plaintext is not permitted in production")
	}
	fu, err := url.Parse(c.OpenFGA.URL)
	if err != nil || fu.Host == "" || (fu.Scheme != "https" && fu.Scheme != "http") {
		return errors.New("config: openfga.url must be an http(s) URL")
	}
	if fu.Scheme == "http" && !c.OpenFGA.AllowPlaintext {
		return errors.New("config: openfga.url is plaintext; set openfga.allow_plaintext only for development")
	}
	if prod && c.OpenFGA.AllowPlaintext {
		return errors.New("config: openfga.allow_plaintext is not permitted in production")
	}
	if c.OpenFGA.PresharedKey == "" {
		return errors.New("config: openfga.preshared_key is required")
	}
	if _, err := c.KEK.Load(); err != nil {
		return err
	}
	switch c.Email.Transport {
	case "notification", "smtp":
	case "log":
		if prod {
			return errors.New("config: email.transport=log is not permitted in production")
		}
	default:
		return fmt.Errorf("config: email.transport %q must be notification or log", c.Email.Transport)
	}
	if c.Token.AccessLifetime <= 0 || c.Token.AccessLifetime > 15*time.Minute {
		return errors.New("config: token.access_lifetime must be within 1s..15m")
	}
	if c.Token.RetiringPeriod < c.Token.AccessLifetime+c.Token.ClockSkew {
		return errors.New("config: token.retiring_period must cover access_lifetime + clock_skew")
	}
	if c.Token.RotationInterval < time.Hour || c.Token.ClockSkew < 0 || c.Token.ClockSkew > 5*time.Minute {
		return errors.New("config: token.rotation_interval must be ≥1h and clock_skew within 0..5m")
	}
	if c.Session.RevocationPoll <= 0 || c.Session.RevocationPoll > 30*time.Second {
		return errors.New("config: session.revocation_poll must be within 1s..30s")
	}
	return c.Directory.validate(prod)
}

func (d *Directory) validate(prod bool) error {
	for _, s := range d.Targets.DenyCIDRs {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("config: directory.targets.deny_cidrs: %q is not a CIDR", s)
		}
	}
	for _, s := range d.Targets.AllowCIDRs {
		if _, err := netip.ParsePrefix(s); err != nil {
			return fmt.Errorf("config: directory.targets.allow_cidrs: %q is not a CIDR", s)
		}
	}
	if len(d.Targets.AllowedPorts) == 0 {
		return errors.New("config: directory.targets.allowed_ports must list at least one port")
	}
	for _, p := range d.Targets.AllowedPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("config: directory.targets.allowed_ports: %d is outside 1..65535", p)
		}
	}
	if d.DialTimeout <= 0 || d.DialTimeout > 30*time.Second {
		return errors.New("config: directory.dial_timeout must be within (0, 30s]")
	}
	if d.MaxSizeLimit < 1 || d.MaxSizeLimit > 1000 {
		return errors.New("config: directory.max_size_limit must be within [1, 1000]")
	}
	if d.MaxTimeLimit < time.Second || d.MaxTimeLimit > 60*time.Second {
		return errors.New("config: directory.max_time_limit must be within [1s, 60s]")
	}
	if d.RatePerMinute <= 0 {
		return errors.New("config: directory.rate_per_minute must be positive")
	}
	if d.MaxConnectionsPerTenant <= 0 {
		return errors.New("config: directory.max_connections_per_tenant must be positive")
	}
	return nil
}

// Warnings lists accepted insecure conveniences (development only).
func (c Config) Warnings() []string {
	w := c.Config.Warnings()
	if c.Gateway.Enabled {
		w = append(w, "gateway mode: browser protections (CSRF, security headers, rate limits) are delegated to the gateway")
	} else if c.Edge.CertFile == "" {
		w = append(w, "edge listener will use a generated self-signed certificate")
	}
	if c.Valkey.AllowPlaintext {
		w = append(w, "valkey connection without TLS (allow_plaintext)")
	}
	if c.OpenFGA.AllowPlaintext {
		w = append(w, "openfga connection without TLS (allow_plaintext)")
	}
	if keys := c.Email.ignored(); len(keys) > 0 {
		w = append(w, "email: "+strings.Join(keys, ", ")+" ignored: mail is delivered by notification (remove these keys; they are refused in v5)")
	}
	if c.Email.Mode() == "log" {
		w = append(w, "email goes to the log sink with its links (development only)")
	}
	if !strings.Contains(c.DB.DSN, "sslmode=verify-full") && !strings.Contains(c.DB.DSN, "sslmode=verify-ca") {
		w = append(w, "db.dsn sslmode is weaker than verify-full")
	}
	if c.Directory.AllowPlaintext {
		w = append(w, "directory connections may use ldap:// without TLS (directory.allow_plaintext)")
	}
	if len(c.Directory.Targets.AllowCIDRs) > 0 {
		w = append(w, "directory.targets.allow_cidrs overrides deny_cidrs for: "+strings.Join(c.Directory.Targets.AllowCIDRs, ", "))
	}
	return w
}

// Load returns the 32-byte key-encryption key.
func (k KEK) Load() ([]byte, error) {
	var raw string
	switch k.Source {
	case "file":
		b, err := os.ReadFile(k.Path) // #nosec G304 -- operator-supplied secret path
		if err != nil {
			return nil, fmt.Errorf("config: kek: %w", err)
		}
		raw = string(b)
	case "env":
		v, ok := os.LookupEnv(k.Env)
		if !ok || v == "" {
			return nil, fmt.Errorf("config: kek: environment variable %q is not set", k.Env)
		}
		raw = v
	default:
		return nil, fmt.Errorf("config: kek.source %q must be file or env", k.Source)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(key) != 32 {
		return nil, errors.New("config: kek must be 32 bytes, base64-encoded")
	}
	return key, nil
}
