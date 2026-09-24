package ldapdir

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/config"
)

// defaultTargets mirrors the D15 config default: no CIDR lists, the four LDAP
// ports.
func defaultTargets() config.DirectoryTargets {
	return config.DirectoryTargets{AllowedPorts: []int{389, 636, 3268, 3269}}
}

func mustPolicy(t *testing.T, cfg config.DirectoryTargets) *TargetPolicy {
	t.Helper()
	p, err := NewTargetPolicy(cfg)
	if err != nil {
		t.Fatalf("NewTargetPolicy(%+v): %v", cfg, err)
	}
	return p
}

// alwaysDenied is the set no config can open (research D5).
var alwaysDenied = []string{
	// loopback
	"127.0.0.1", "127.0.0.53", "127.255.255.254", "::1",
	// link-local incl. cloud metadata
	"169.254.169.254", "169.254.0.1", "169.254.255.254", "fe80::1", "febf:ffff::1",
	// unspecified
	"0.0.0.0", "::",
	// multicast
	"224.0.0.1", "239.255.255.250", "ff02::1", "ff05::1:3",
	// IPv4-mapped forms of the above
	"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:0.0.0.0", "::ffff:224.0.0.1",
}

func TestNewTargetPolicyRejectsBadConfig(t *testing.T) {
	cases := map[string]config.DirectoryTargets{
		"bad deny cidr":   {DenyCIDRs: []string{"10.0.0.0/33"}, AllowedPorts: []int{636}},
		"bad allow cidr":  {AllowCIDRs: []string{"not-a-cidr"}, AllowedPorts: []int{636}},
		"bare ip as cidr": {DenyCIDRs: []string{"10.0.0.1"}, AllowedPorts: []int{636}},
		"no ports":        {},
		"port zero":       {AllowedPorts: []int{0}},
		"port too large":  {AllowedPorts: []int{65536}},
		"negative port":   {AllowedPorts: []int{636, -1}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if p, err := NewTargetPolicy(cfg); err == nil {
				t.Fatalf("NewTargetPolicy(%+v) = %v, want error", cfg, p)
			}
		})
	}
}

func TestControlAlwaysDenied(t *testing.T) {
	// Even an allow_cidrs covering everything cannot open the always-denied set.
	opened := defaultTargets()
	opened.AllowCIDRs = []string{"0.0.0.0/0", "::/0", "127.0.0.0/8", "169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8"}
	for name, cfg := range map[string]config.DirectoryTargets{"default": defaultTargets(), "allow everything": opened} {
		p := mustPolicy(t, cfg)
		for _, ip := range alwaysDenied {
			for _, network := range []string{"tcp", "tcp4", "tcp6"} {
				addr := net.JoinHostPort(ip, "636")
				if err := p.Control(network, addr, nil); !errors.Is(err, ErrTargetRefused) {
					t.Errorf("%s: Control(%q, %q) = %v, want ErrTargetRefused", name, network, addr, err)
				}
			}
		}
	}
}

func TestControlAllowsOrdinaryTargets(t *testing.T) {
	p := mustPolicy(t, defaultTargets())
	// Private ranges are not denied by default: customer directories live there.
	for _, addr := range []string{
		"192.0.2.10:636", "203.0.113.5:389", "10.0.0.5:3268", "172.16.1.1:3269",
		"192.168.1.10:636", "[2001:db8::10]:636", "[::ffff:192.0.2.10]:636",
	} {
		if err := p.Control("tcp4", addr, nil); err != nil {
			t.Errorf("Control(%q) = %v, want nil", addr, err)
		}
	}
}

func TestControlDenyCIDRs(t *testing.T) {
	cfg := defaultTargets()
	cfg.DenyCIDRs = []string{"10.0.0.0/8", "fd00::/8"}
	p := mustPolicy(t, cfg)
	for _, addr := range []string{"10.0.0.5:636", "10.255.255.254:389", "[fd00::5]:636", "[::ffff:10.1.2.3]:636"} {
		if err := p.Control("tcp", addr, nil); !errors.Is(err, ErrTargetRefused) {
			t.Errorf("Control(%q) = %v, want ErrTargetRefused", addr, err)
		}
	}
	for _, addr := range []string{"11.0.0.1:636", "192.0.2.10:636", "[fc00::5]:636"} {
		if err := p.Control("tcp", addr, nil); err != nil {
			t.Errorf("Control(%q) = %v, want nil", addr, err)
		}
	}
}

func TestControlAllowCIDRsOverrideDenyCIDRs(t *testing.T) {
	cfg := defaultTargets()
	cfg.DenyCIDRs = []string{"10.0.0.0/8", "fd00::/8"}
	cfg.AllowCIDRs = []string{"10.1.0.0/16", "fd00:1::/32"}
	p := mustPolicy(t, cfg)
	for _, addr := range []string{"10.1.2.3:636", "[fd00:1::5]:636", "[::ffff:10.1.2.3]:636"} {
		if err := p.Control("tcp", addr, nil); err != nil {
			t.Errorf("Control(%q) = %v, want nil (allow_cidrs override)", addr, err)
		}
	}
	for _, addr := range []string{"10.2.0.1:636", "[fd00:2::5]:636"} {
		if err := p.Control("tcp", addr, nil); !errors.Is(err, ErrTargetRefused) {
			t.Errorf("Control(%q) = %v, want ErrTargetRefused", addr, err)
		}
	}
	// allow_cidrs is an override, not an allow-only list.
	if err := p.Control("tcp", "192.0.2.10:636", nil); err != nil {
		t.Errorf("Control outside both lists = %v, want nil", err)
	}
	// An allowed address still needs an allowed port.
	if err := p.Control("tcp", "10.1.2.3:5432", nil); !errors.Is(err, ErrTargetRefused) {
		t.Errorf("Control(10.1.2.3:5432) = %v, want ErrTargetRefused", err)
	}
}

func TestControlAllowedPorts(t *testing.T) {
	p := mustPolicy(t, defaultTargets())
	for _, port := range []string{"389", "636", "3268", "3269"} {
		if err := p.Control("tcp", net.JoinHostPort("192.0.2.10", port), nil); err != nil {
			t.Errorf("port %s: %v, want nil", port, err)
		}
	}
	for _, port := range []string{"22", "80", "443", "5432", "6379", "8080", "8443", "65535"} {
		if err := p.Control("tcp", net.JoinHostPort("192.0.2.10", port), nil); !errors.Is(err, ErrTargetRefused) {
			t.Errorf("port %s: %v, want ErrTargetRefused", port, err)
		}
	}

	custom := mustPolicy(t, config.DirectoryTargets{AllowedPorts: []int{10636}})
	if err := custom.Control("tcp", "192.0.2.10:10636", nil); err != nil {
		t.Errorf("custom port 10636: %v, want nil", err)
	}
	if err := custom.Control("tcp", "192.0.2.10:636", nil); !errors.Is(err, ErrTargetRefused) {
		t.Errorf("636 not in custom list: %v, want ErrTargetRefused", err)
	}
}

func TestControlFailsClosedOnOddInput(t *testing.T) {
	p := mustPolicy(t, defaultTargets())
	cases := []struct{ network, address string }{
		{"udp", "192.0.2.10:389"},     // LDAP over TCP only
		{"unix", "/run/ldap.sock"},    // never a socket path
		{"tcp", "192.0.2.10"},         // no port
		{"tcp", "192.0.2.10:ldaps"},   // named port, never resolved by the dialer
		{"tcp", "192.0.2.10:99999"},   // out of range
		{"tcp", "dc.example.com:636"}, // Control only ever sees resolved IPs
		{"tcp", "[fe80::1%eth0]:636"}, // zoned address
		{"tcp", ""},
	}
	for _, c := range cases {
		if err := p.Control(c.network, c.address, nil); !errors.Is(err, ErrTargetRefused) {
			t.Errorf("Control(%q, %q) = %v, want ErrTargetRefused", c.network, c.address, err)
		}
	}
}

// TestControlRefusesResolvedAddress dials through a real net.Dialer: the
// hostname passes save-time checks, but the address it resolves to is refused
// before connect, so a local listener never sees the connection.
func TestControlRefusesResolvedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	// Allow the listener's port so only the address decides.
	p := mustPolicy(t, config.DirectoryTargets{AllowedPorts: []int{port}})
	d := &net.Dialer{Timeout: 2 * time.Second, Control: p.Control}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, host := range []string{"127.0.0.1", "localhost"} {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("dial %s succeeded, want refusal", addr)
		}
		if !errors.Is(err, ErrTargetRefused) {
			t.Fatalf("dial %s = %v, want ErrTargetRefused", addr, err)
		}
	}
	select {
	case <-accepted:
		t.Fatal("listener accepted a connection the policy should have refused")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCheckURLAccepts(t *testing.T) {
	p := mustPolicy(t, defaultTargets())
	cases := []struct {
		raw  string
		want Endpoint
		addr string
	}{
		{"ldaps://dc.example.com", Endpoint{Scheme: "ldaps", Host: "dc.example.com", Port: 636}, "dc.example.com:636"},
		{"ldap://dc.example.com", Endpoint{Scheme: "ldap", Host: "dc.example.com", Port: 389}, "dc.example.com:389"},
		{"ldaps://dc.example.com:3269", Endpoint{Scheme: "ldaps", Host: "dc.example.com", Port: 3269}, "dc.example.com:3269"},
		{"ldap://gc.example.com:3268", Endpoint{Scheme: "ldap", Host: "gc.example.com", Port: 3268}, "gc.example.com:3268"},
		{"LDAPS://dc.example.com", Endpoint{Scheme: "ldaps", Host: "dc.example.com", Port: 636}, "dc.example.com:636"},
		{"ldaps://192.0.2.10", Endpoint{Scheme: "ldaps", Host: "192.0.2.10", Port: 636}, "192.0.2.10:636"},
		{"ldaps://10.0.0.5:636", Endpoint{Scheme: "ldaps", Host: "10.0.0.5", Port: 636}, "10.0.0.5:636"},
		{"ldaps://[2001:db8::10]", Endpoint{Scheme: "ldaps", Host: "2001:db8::10", Port: 636}, "[2001:db8::10]:636"},
		{"ldap://[2001:db8::10]:389", Endpoint{Scheme: "ldap", Host: "2001:db8::10", Port: 389}, "[2001:db8::10]:389"},
	}
	for _, c := range cases {
		got, err := p.CheckURL(c.raw)
		if err != nil {
			t.Errorf("CheckURL(%q) = %v, want nil", c.raw, err)
			continue
		}
		if got != c.want {
			t.Errorf("CheckURL(%q) = %+v, want %+v", c.raw, got, c.want)
		}
		if a := got.Addr(); a != c.addr {
			t.Errorf("CheckURL(%q).Addr() = %q, want %q", c.raw, a, c.addr)
		}
	}
}

func TestCheckURLInvalid(t *testing.T) {
	p := mustPolicy(t, defaultTargets())
	for _, raw := range []string{
		"",
		"dc.example.com",                           // no scheme
		"https://dc.example.com",                   // wrong scheme
		"ldapi:///var/run/slapd.sock",              // unix-socket LDAP
		"cldap://dc.example.com",                   // UDP LDAP
		"ldap:dc.example.com",                      // opaque
		"ldap://",                                  // host required
		"ldaps://:636",                             // host required
		"ldaps://user@dc.example.com",              // userinfo
		"ldaps://cn=admin:secret@dc.example.com",   // userinfo with password
		"ldaps://dc.example.com/",                  // path
		"ldaps://dc.example.com/dc=example,dc=com", // RFC 4516 DN path
		"ldaps://dc.example.com?uid",               // query
		"ldaps://dc.example.com#frag",              // fragment
		"ldaps://dc.example.com:",                  // empty port
		"ldaps://dc.example.com:0",                 // port out of range
		"ldaps://dc.example.com:65536",             // port out of range
		"ldaps://dc.example.com:ldaps",             // named port
		"ldaps://dc.example.com:389:636",           // parses as host "dc.example.com:389"
		"ldap://::1",                               // unbracketed IPv6 parses as host ":" port "1"
		"ldaps://[2001:db8::10",                    // unterminated bracket
		"ldaps://[2001:db8::1%25eth0]:636",         // zoned IPv6
		"ldaps://dc.example.com\x00.evil",          // control character
		" ldaps://dc.example.com",                  // leading space
	} {
		_, err := p.CheckURL(raw)
		if !errors.Is(err, ErrInvalidURL) {
			t.Errorf("CheckURL(%q) = %v, want ErrInvalidURL", raw, err)
		}
	}
}

func TestCheckURLErrorDoesNotEchoSecrets(t *testing.T) {
	p := mustPolicy(t, defaultTargets())
	_, err := p.CheckURL("ldaps://cn=admin:S3cr3t-Pa55@dc.example.com")
	if err == nil {
		t.Fatal("CheckURL with userinfo succeeded")
	}
	if strings.Contains(err.Error(), "S3cr3t-Pa55") {
		t.Fatalf("error leaks the password: %q", err.Error())
	}
}

func TestCheckURLPortPolicy(t *testing.T) {
	p := mustPolicy(t, defaultTargets())
	for _, raw := range []string{
		"ldap://dc.example.com:5432",
		"ldaps://dc.example.com:6379",
		"ldaps://dc.example.com:443",
		"ldaps://[2001:db8::10]:8443",
	} {
		if _, err := p.CheckURL(raw); !errors.Is(err, ErrTargetRefused) {
			t.Errorf("CheckURL(%q) = %v, want ErrTargetRefused", raw, err)
		}
	}

	// The scheme's default port is checked against allowed_ports as well.
	only := mustPolicy(t, config.DirectoryTargets{AllowedPorts: []int{636}})
	if _, err := only.CheckURL("ldap://dc.example.com"); !errors.Is(err, ErrTargetRefused) {
		t.Errorf("ldap default port 389 not allowed: %v, want ErrTargetRefused", err)
	}
	if _, err := only.CheckURL("ldaps://dc.example.com"); err != nil {
		t.Errorf("ldaps default port 636 allowed: %v, want nil", err)
	}
}

func TestCheckURLLiteralIPPreCheck(t *testing.T) {
	cfg := defaultTargets()
	cfg.DenyCIDRs = []string{"10.0.0.0/8"}
	cfg.AllowCIDRs = []string{"10.1.0.0/16", "127.0.0.0/8"}
	p := mustPolicy(t, cfg)

	for _, ip := range alwaysDenied {
		host := ip
		if strings.Contains(ip, ":") {
			host = "[" + ip + "]"
		}
		raw := "ldaps://" + host + ":636"
		if _, err := p.CheckURL(raw); !errors.Is(err, ErrTargetRefused) {
			t.Errorf("CheckURL(%q) = %v, want ErrTargetRefused", raw, err)
		}
	}
	if _, err := p.CheckURL("ldaps://10.2.0.1"); !errors.Is(err, ErrTargetRefused) {
		t.Errorf("deny_cidrs literal: %v, want ErrTargetRefused", err)
	}
	if _, err := p.CheckURL("ldaps://10.1.2.3"); err != nil {
		t.Errorf("allow_cidrs literal: %v, want nil", err)
	}
	// Hostnames are not resolved at save time; Control checks them at dial.
	if _, err := p.CheckURL("ldaps://dc.internal.example"); err != nil {
		t.Errorf("hostname: %v, want nil", err)
	}
}
