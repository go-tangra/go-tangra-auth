//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/config"
)

// TestLDAPSSRFTargetPolicy is the quickstart SSRF check: the real policy
// dialer refuses loopback literals, the cloud metadata address, a hostname
// that resolves to loopback, the TimescaleDB container's own address on a
// non-LDAP port and a deny_cidrs address — every refusal is the coarse
// target_refused outcome. An address covered by allow_cidrs is actually
// dialled and its dead port reports only unreachable. Responses never reveal
// which address or port was probed.
func TestLDAPSSRFTargetPolicy(t *testing.T) {
	e := Start(t, func(cfg *config.Config, dbAddr string) {
		cfg.Directory.AllowPlaintext = true // dev opt-out; the harness env is "test"
		cfg.Directory.Targets.DenyCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"}
		suffix := 32
		if netip.MustParseAddr(dbAddr).Is6() {
			suffix = 128
		}
		cfg.Directory.Targets.AllowCIDRs = []string{fmt.Sprintf("%s/%d", dbAddr, suffix)}
	})
	pg := e.PGIP
	if _, err := netip.ParseAddr(pg); err != nil {
		t.Fatalf("timescaledb address %q: %v", pg, err)
	}
	// An address inside deny_cidrs that allow_cidrs does not cover.
	denied := netip.MustParseAddr(pg).Next().String()

	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}

	// probe runs the unsaved-connection test endpoint: one real dial attempt
	// per call, the outcome limited to a step plus a closed reason.
	probe := func(rawURL, tlsMode string) map[string]any {
		t.Helper()
		code, out := e.JSON(http.MethodPost, "/api/v1/admin/directories/test", map[string]any{
			"name":          "ssrf-probe",
			"kind":          "openldap",
			"url":           rawURL,
			"tls_mode":      tlsMode,
			"bind_dn":       "cn=reader,dc=example,dc=test",
			"bind_password": "reader-password",
			"base_dn":       "dc=example,dc=test",
		})
		if code != http.StatusOK {
			t.Fatalf("test %s → %d %v", rawURL, code, out)
		}
		return out
	}
	// check asserts the coarse outcome and that the response reveals neither
	// the container address nor the denied address (no probe oracle).
	check := func(name string, out map[string]any, reason string) {
		t.Helper()
		if out["ok"] != false || out["step"] != "connect" || out["reason"] != reason {
			t.Errorf("%s: got %v, want ok=false step=connect reason=%s", name, out, reason)
		}
		b, _ := json.Marshal(out)
		if strings.Contains(string(b), pg) || strings.Contains(string(b), denied) {
			t.Errorf("%s: response reveals the probed address: %s", name, b)
		}
	}

	refused := []struct {
		name    string
		url     string
		tlsMode string
	}{
		{"ipv4 loopback literal", "ldap://127.0.0.1:389", "plain"},
		{"ipv6 loopback literal", "ldaps://[::1]:636", "ldaps"},
		{"cloud metadata address", "ldap://169.254.169.254:389", "plain"},
		{"hostname resolving to loopback", "ldap://localhost:389", "plain"},
		{"database container port 5432", "ldap://" + net.JoinHostPort(pg, "5432"), "plain"},
		{"deny_cidrs address", "ldap://" + net.JoinHostPort(denied, "389"), "plain"},
	}
	for _, tc := range refused {
		check(tc.name, probe(tc.url, tc.tlsMode), "target_refused")
	}

	// The same container address covered by allow_cidrs is dialled: nothing
	// listens on the LDAP port there, so the coarse outcome is unreachable.
	check("allow_cidrs override", probe("ldap://"+net.JoinHostPort(pg, "389"), "plain"), "unreachable")

	if n := e.AuditCount(tid, string(audit.DirectoryConnectionTested)); n != len(refused)+1 {
		t.Errorf("directory_connection_tested audit rows = %d, want %d", n, len(refused)+1)
	}
}
