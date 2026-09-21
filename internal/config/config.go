package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	fconfig "github.com/go-freya/freya/config"
	"github.com/go-freya/freya/transport/edge"
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

// Email configures the SMTP sender.
type Email struct {
	Transport      string `yaml:"transport"` // smtp | log
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	From           string `yaml:"from"`
	AllowPlaintext bool   `yaml:"allow_plaintext"`
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
		Email:   Email{Transport: "smtp", Port: 465},
		Token:   Token{AccessLifetime: 15 * time.Minute, RotationInterval: 24 * time.Hour, RetiringPeriod: 30 * time.Minute, ClockSkew: 60 * time.Second},
		Session: Session{RevocationPoll: 5 * time.Second},
		Gateway: Gateway{Service: "gateway"},
		Profile: Profile{AvatarMaxBytes: 2 << 20, AvatarMaxPixels: 4096 * 4096, AvatarSize: 512, AvatarDecodeConcurrency: 4, LookupRatePerMinute: 120},
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
	case "smtp":
		if c.Email.Host == "" || c.Email.Port <= 0 {
			return errors.New("config: email.host and email.port are required")
		}
	case "log":
		if prod {
			return errors.New("config: email.transport=log is not permitted in production")
		}
	default:
		return fmt.Errorf("config: email.transport %q must be smtp or log", c.Email.Transport)
	}
	if c.Email.From == "" {
		return errors.New("config: email.from is required")
	}
	if prod && c.Email.AllowPlaintext {
		return errors.New("config: email.allow_plaintext is not permitted in production")
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
	if c.Email.AllowPlaintext || c.Email.Transport == "log" {
		w = append(w, "email delivery without TLS or to the log sink")
	}
	if !strings.Contains(c.DB.DSN, "sslmode=verify-full") && !strings.Contains(c.DB.DSN, "sslmode=verify-ca") {
		w = append(w, "db.dsn sslmode is weaker than verify-full")
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
