package ldapdir

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-freya/freya/services/auth/internal/config"
)

var (
	// ErrTargetRefused means the target address or port is outside the dial policy.
	ErrTargetRefused = errors.New("ldapdir: target refused")
	// ErrInvalidURL means the directory URL is not a plain ldap(s)://host[:port].
	ErrInvalidURL = errors.New("ldapdir: invalid directory URL")
)

// Default ports per scheme (RFC 4516 / common practice).
const (
	defaultLDAPPort  = 389
	defaultLDAPSPort = 636
)

// thisNetwork (0.0.0.0/8) is denied with the unspecified address: Linux treats
// it as "this host" for some destinations.
var thisNetwork = netip.MustParsePrefix("0.0.0.0/8")

// Endpoint is a validated directory address. Host carries no IPv6 brackets.
type Endpoint struct {
	Scheme string
	Host   string
	Port   int
}

// Addr is the host:port form for dialling.
func (e Endpoint) Addr() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// TargetPolicy decides whether a directory target may be dialled (research
// D5). The always-denied set is enforced in code; allow CIDRs only override
// deny CIDRs; every target needs an allowed port.
type TargetPolicy struct {
	deny  []netip.Prefix
	allow []netip.Prefix
	ports map[int]struct{}
}

// NewTargetPolicy compiles cfg. It repeats the config validation so a policy
// can never be built from unchecked input.
func NewTargetPolicy(cfg config.DirectoryTargets) (*TargetPolicy, error) {
	deny, err := parsePrefixes("deny_cidrs", cfg.DenyCIDRs)
	if err != nil {
		return nil, err
	}
	allow, err := parsePrefixes("allow_cidrs", cfg.AllowCIDRs)
	if err != nil {
		return nil, err
	}
	if len(cfg.AllowedPorts) == 0 {
		return nil, errors.New("ldapdir: allowed_ports must list at least one port")
	}
	ports := make(map[int]struct{}, len(cfg.AllowedPorts))
	for _, p := range cfg.AllowedPorts {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("ldapdir: allowed_ports: %d is outside 1..65535", p)
		}
		ports[p] = struct{}{}
	}
	return &TargetPolicy{deny: deny, allow: allow, ports: ports}, nil
}

func parsePrefixes(field string, in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("ldapdir: %s: %q is not a CIDR", field, s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Dialer returns a net.Dialer whose Control hook enforces the policy on every
// address actually dialled, so hostnames and DNS rebinding cannot bypass it.
func (p *TargetPolicy) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: p.Control}
}

// Control is a net.Dialer Control hook. It sees the resolved IP:port and fails
// closed on anything else.
func (p *TargetPolicy) Control(network, address string, _ syscall.RawConn) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("%w: network not allowed", ErrTargetRefused)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: malformed address", ErrTargetRefused)
	}
	n, ok := parsePort(port)
	if !ok {
		return fmt.Errorf("%w: malformed port", ErrTargetRefused)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return fmt.Errorf("%w: not a resolved address", ErrTargetRefused)
	}
	if err := p.checkPort(n); err != nil {
		return err
	}
	return p.checkIP(ip)
}

// CheckURL validates a directory URL at save time: scheme ldap|ldaps, a host,
// optional numeric port and nothing else. The port must be allowed and an
// IP-literal host must pass the address policy; hostnames are left to Control.
// Errors never echo the input, which may carry credentials.
func (p *TargetPolicy) CheckURL(raw string) (Endpoint, error) {
	if raw == "" || strings.IndexFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }) >= 0 {
		return Endpoint{}, fmt.Errorf("%w: empty or contains control characters", ErrInvalidURL)
	}
	if strings.ContainsAny(raw, "?#") {
		return Endpoint{}, fmt.Errorf("%w: query or fragment not allowed", ErrInvalidURL)
	}
	u, err := url.Parse(raw)
	if err != nil { // the url.Error quotes the input; never wrap it
		return Endpoint{}, fmt.Errorf("%w: unparseable", ErrInvalidURL)
	}
	var defPort int
	switch u.Scheme { // url.Parse lowercases the scheme
	case "ldap":
		defPort = defaultLDAPPort
	case "ldaps":
		defPort = defaultLDAPSPort
	default:
		return Endpoint{}, fmt.Errorf("%w: scheme must be ldap or ldaps", ErrInvalidURL)
	}
	if u.Opaque != "" || u.User != nil || u.Path != "" || u.RawPath != "" {
		return Endpoint{}, fmt.Errorf("%w: only scheme, host and port are allowed", ErrInvalidURL)
	}
	host, portStr, isIP, err := splitURLHost(u.Host)
	if err != nil {
		return Endpoint{}, err
	}
	port := defPort
	if portStr != "" {
		n, ok := parsePort(portStr)
		if !ok {
			return Endpoint{}, fmt.Errorf("%w: port must be 1..65535", ErrInvalidURL)
		}
		port = n
	}
	if err := p.checkPort(port); err != nil {
		return Endpoint{}, err
	}
	if isIP {
		if err := p.checkIP(netip.MustParseAddr(host)); err != nil {
			return Endpoint{}, err
		}
	}
	return Endpoint{Scheme: u.Scheme, Host: host, Port: port}, nil
}

// splitURLHost splits u.Host into host and the port text after ':' ("" when
// absent). Bracketed hosts must be unzoned IPv6 literals; unbracketed hosts
// are IPv4 literals or DNS names and may not contain another ':'.
func splitURLHost(h string) (host, port string, isIP bool, err error) {
	var rest string
	if strings.HasPrefix(h, "[") {
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return "", "", false, fmt.Errorf("%w: unterminated IPv6 literal", ErrInvalidURL)
		}
		host, rest = h[1:end], h[end+1:]
		ip, perr := netip.ParseAddr(host)
		if perr != nil || !ip.Is6() || ip.Zone() != "" {
			return "", "", false, fmt.Errorf("%w: bracketed host must be an unzoned IPv6 address", ErrInvalidURL)
		}
		isIP = true
	} else {
		host, rest = h, ""
		if i := strings.IndexByte(h, ':'); i >= 0 {
			host, rest = h[:i], h[i:]
		}
		if ip, perr := netip.ParseAddr(host); perr == nil && ip.Is4() {
			isIP = true
		} else if !validHostname(host) {
			return "", "", false, fmt.Errorf("%w: host is not a valid name or address", ErrInvalidURL)
		}
	}
	if rest != "" {
		if rest[0] != ':' || len(rest) == 1 {
			return "", "", false, fmt.Errorf("%w: malformed port", ErrInvalidURL)
		}
		port = rest[1:]
	}
	return host, port, isIP, nil
}

// validHostname accepts DNS names of letters, digits, '-' and '_' (AD SRV
// style) with 1..63-byte labels and ≤253 bytes overall. An all-numeric last
// label is refused so numeric IP spellings (e.g. "2130706433", "010.0.0.1")
// cannot pass as names.
func validHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		if strings.IndexFunc(l, notHostnameChar) >= 0 {
			return false
		}
	}
	return !allDigits(labels[len(labels)-1])
}

func notHostnameChar(r rune) bool {
	return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_'
}

// parsePort accepts 1..5 ASCII digits in 1..65535 (no sign, no names).
func parsePort(s string) (int, bool) {
	if s == "" || len(s) > 5 || !allDigits(s) {
		return 0, false
	}
	n, _ := strconv.Atoi(s)
	return n, n >= 1 && n <= 65535
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (p *TargetPolicy) checkPort(port int) error {
	if _, ok := p.ports[port]; !ok {
		return fmt.Errorf("%w: port not allowed", ErrTargetRefused)
	}
	return nil
}

// checkIP applies the always-denied set, then deny_cidrs unless allow_cidrs
// covers the address. IPv4-mapped IPv6 addresses are unmapped first.
func (p *TargetPolicy) checkIP(ip netip.Addr) error {
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || thisNetwork.Contains(ip) {
		return fmt.Errorf("%w: address class is never dialled", ErrTargetRefused)
	}
	if inAny(p.deny, ip) && !inAny(p.allow, ip) {
		return fmt.Errorf("%w: address in a denied range", ErrTargetRefused)
	}
	return nil
}

// inAny reports whether ip is in any prefix. An IPv4 address is also matched
// in its IPv4-mapped form, so "::ffff:10.0.0.0/104" or "::/0" cover it too.
func inAny(prefixes []netip.Prefix, ip netip.Addr) bool {
	mapped := netip.AddrFrom16(ip.As16())
	for _, pf := range prefixes {
		if pf.Contains(ip) || (ip.Is4() && pf.Contains(mapped)) {
			return true
		}
	}
	return false
}
