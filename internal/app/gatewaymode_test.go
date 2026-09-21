package app

import (
	"strings"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/config"
	"github.com/go-freya/freya/services/auth/pkg/authmanifest"
)

func TestGatewayModeConfig(t *testing.T) {
	c := config.Default()
	c.ServiceName, c.TrustDomain = "auth", "example.org"
	c.Authz.Source, c.Authz.Path = "file", "p.yaml"
	c.Issuer = "https://platform.example.org"
	c.DB.DSN = "postgres://u@db/auth?sslmode=verify-full"
	c.Valkey.Addresses = []string{"v:6379"}
	c.OpenFGA.URL, c.OpenFGA.PresharedKey = "https://fga", "k"
	c.KEK.Source, c.KEK.Env = "env", "KEK"
	t.Setenv("KEK", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	c.Email.Transport, c.Email.Host, c.Email.Port, c.Email.From = "smtp", "m", 465, "a@x"
	c.Gateway.Enabled = true
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "http_addr") {
		t.Fatalf("gateway mode without http_addr accepted: %v", err)
	}
	c.Server.HTTPAddr = "127.0.0.1:0"
	c.Gateway.Service = ""
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "gateway.service") {
		t.Fatalf("missing service accepted: %v", err)
	}
	c.Gateway.Service = "gateway"
	c.Env = "production"
	c.Valkey.AllowPlaintext = false
	// Production without edge certificates is fine in gateway mode (no edge listener).
	if err := c.Validate(); err != nil {
		t.Fatalf("gateway mode in production: %v", err)
	}
	found := false
	for _, w := range c.Warnings() {
		if strings.Contains(w, "gateway mode") {
			found = true
		}
	}
	if !found {
		t.Fatal("gateway mode warning missing")
	}
}

func TestAuthManifestDeclaresEveryRoute(t *testing.T) {
	m, err := authmanifest.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.Module != "auth" || len(m.Prefixes) != 4 || len(m.Routes) < 30 {
		t.Fatalf("%+v", m)
	}
	have := map[string]bool{}
	for _, r := range m.Routes {
		if !r.Public || r.Permission != "" {
			t.Fatalf("auth routes must be public at the gateway: %+v", r)
		}
		have[r.Method+" "+r.Path] = true
	}
	for _, want := range []string{"POST /api/v1/signin", "GET /api/v1/session", "POST /api/v1/signout", "GET /console/{path...}", "GET /console"} {
		if !have[want] {
			t.Fatalf("%s missing", want)
		}
	}
	perms := map[string]bool{}
	for _, p := range m.Permissions {
		perms[p.Resource+":"+p.Action] = true
	}
	for _, a := range m.Abilities {
		if !perms[a.Requires] {
			t.Fatalf("ability requires unknown permission %s", a.Requires)
		}
	}
	for _, n := range m.Nav {
		if !perms[n.Requires] {
			t.Fatalf("nav requires unknown permission %s", n.Requires)
		}
	}
	for slug, refs := range authmanifest.Grants {
		for _, r := range refs {
			if !perms[r] {
				t.Fatalf("grant %s → %s unknown", slug, r)
			}
		}
	}
	if _, err := m.Proto(); err != nil {
		t.Fatal(err)
	}
}
