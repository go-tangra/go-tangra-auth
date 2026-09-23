package ldapdir

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/go-freya/freya/services/auth/internal/config"
)

// The real client is exercised against a scripted in-process LDAPv3 server on
// loopback. Loopback is in the always-denied set, so these tests swap the
// client's dialer for a plain one (the unexported dialer seam); the policy
// dialer itself is covered by TestOpenDialsThroughPolicy.

// ---- scripted LDAP server --------------------------------------------------

const startTLSOID = "1.3.6.1.4.1.1466.20037"

// hang as a result code means "never answer this request".
const hang = -1

type testEntry struct {
	dn    string
	attrs map[string][]string
}

type searchReply struct {
	entries []testEntry
	refs    []string
	code    int    // result code of SearchResultDone, or hang
	raw     []byte // written verbatim instead of any reply (hostile packets)
}

type serverScript struct {
	startTLS int // result code for the StartTLS extended request, or hang
	bind     int // result code for BindRequest, or hang
	diag     string
	search   func(searchReq) searchReply
}

type searchReq struct {
	Base      string
	Scope     int64
	Deref     int64
	SizeLimit int64
	TimeLimit int64
	TypesOnly bool
	Filter    string
	Attrs     []string
}

type recordedOp struct {
	Tag      ber.Tag
	OverTLS  bool
	BindDN   string
	Password string
	ExtName  string
	Search   searchReq
}

type ldapTestServer struct {
	t      *testing.T
	ln     net.Listener
	port   int
	ldaps  bool
	tlsCfg *tls.Config // StartTLS upgrade config (and the ldaps listener config)
	script serverScript

	mu      sync.Mutex
	ops     []recordedOp
	accepts int
	conns   []net.Conn
}

// newLDAPServer starts a scripted server on 127.0.0.1. With ldaps set it
// speaks implicit TLS using tlsCfg; otherwise tlsCfg (if any) is used to
// upgrade after a successful StartTLS.
func newLDAPServer(t *testing.T, ldaps bool, tlsCfg *tls.Config, script serverScript) *ldapTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &ldapTestServer{t: t, ln: ln, port: ln.Addr().(*net.TCPAddr).Port, ldaps: ldaps, tlsCfg: tlsCfg, script: script}
	if ldaps {
		s.ln = tls.NewListener(ln, tlsCfg)
	}
	go s.acceptLoop()
	t.Cleanup(s.close)
	return s
}

func (s *ldapTestServer) close() {
	_ = s.ln.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
}

func (s *ldapTestServer) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.accepts++
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		go s.serve(c)
	}
}

func (s *ldapTestServer) record(op *recordedOp) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ops = append(s.ops, *op)
}

func (s *ldapTestServer) recorded() []recordedOp {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedOp(nil), s.ops...)
}

func (s *ldapTestServer) acceptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepts
}

func (s *ldapTestServer) opsWithTag(tag ber.Tag) []recordedOp {
	var out []recordedOp
	ops := s.recorded()
	for i := range ops {
		if ops[i].Tag == tag {
			out = append(out, ops[i])
		}
	}
	return out
}

func (s *ldapTestServer) serve(conn net.Conn) {
	c := conn
	defer func() { _ = c.Close() }()
	overTLS := s.ldaps
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			rec := recordedOp{Tag: op.Tag, OverTLS: overTLS}
			if len(op.Children) >= 3 {
				rec.BindDN, _ = op.Children[1].Value.(string)
				rec.Password = op.Children[2].Data.String()
			}
			s.record(&rec)
			if s.script.bind == hang {
				_, _ = io.Copy(io.Discard, c)
				return
			}
			s.write(c, result(id, ldap.ApplicationBindResponse, s.script.bind, s.script.diag))
		case ldap.ApplicationUnbindRequest:
			s.record(&recordedOp{Tag: op.Tag, OverTLS: overTLS})
			return
		case ldap.ApplicationExtendedRequest:
			name := ""
			if len(op.Children) > 0 {
				name = op.Children[0].Data.String()
			}
			s.record(&recordedOp{Tag: op.Tag, OverTLS: overTLS, ExtName: name})
			if s.script.startTLS == hang {
				_, _ = io.Copy(io.Discard, c)
				return
			}
			s.write(c, result(id, ldap.ApplicationExtendedResponse, s.script.startTLS, s.script.diag))
			if name == startTLSOID && s.script.startTLS == 0 && s.tlsCfg != nil && !overTLS {
				tc := tls.Server(c, s.tlsCfg)
				if tc.Handshake() != nil {
					return
				}
				c, overTLS = tc, true
			}
		case ldap.ApplicationSearchRequest:
			req := parseSearch(op)
			s.record(&recordedOp{Tag: op.Tag, OverTLS: overTLS, Search: req})
			var reply searchReply
			if s.script.search != nil {
				reply = s.script.search(req)
			}
			if reply.raw != nil {
				_, _ = c.Write(reply.raw)
				_, _ = io.Copy(io.Discard, c)
				return
			}
			if reply.code == hang {
				_, _ = io.Copy(io.Discard, c)
				return
			}
			for _, e := range reply.entries {
				s.write(c, entryPacket(id, e))
			}
			for _, r := range reply.refs {
				s.write(c, referencePacket(id, r))
			}
			s.write(c, result(id, ldap.ApplicationSearchResultDone, reply.code, s.script.diag))
		default: // abandon and anything else: no response
			s.record(&recordedOp{Tag: op.Tag, OverTLS: overTLS})
		}
	}
}

func (s *ldapTestServer) write(c net.Conn, p *ber.Packet) {
	_, _ = c.Write(p.Bytes())
}

func envelope(id int64, op *ber.Packet) *ber.Packet {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	env.AppendChild(op)
	return env
}

func octet(s string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s, "")
}

func result(id int64, tag ber.Tag, code int, diag string) *ber.Packet {
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "Result")
	r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "resultCode"))
	r.AppendChild(octet(""))
	if code == 0 {
		diag = ""
	}
	r.AppendChild(octet(diag))
	return envelope(id, r)
}

func entryPacket(id int64, e testEntry) *ber.Packet {
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "Entry")
	r.AppendChild(octet(e.dn))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for name, vals := range e.attrs {
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
		a.AppendChild(octet(name))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")
		for _, v := range vals {
			set.AppendChild(octet(v))
		}
		a.AppendChild(set)
		attrs.AppendChild(a)
	}
	r.AppendChild(attrs)
	return envelope(id, r)
}

func referencePacket(id int64, uri string) *ber.Packet {
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultReference, nil, "Reference")
	r.AppendChild(octet(uri))
	return envelope(id, r)
}

func parseSearch(op *ber.Packet) searchReq {
	var r searchReq
	if len(op.Children) < 8 {
		return r
	}
	r.Base, _ = op.Children[0].Value.(string)
	r.Scope, _ = op.Children[1].Value.(int64)
	r.Deref, _ = op.Children[2].Value.(int64)
	r.SizeLimit, _ = op.Children[3].Value.(int64)
	r.TimeLimit, _ = op.Children[4].Value.(int64)
	r.TypesOnly, _ = op.Children[5].Value.(bool)
	if f, err := ldap.DecompileFilter(op.Children[6]); err == nil {
		r.Filter = f
	}
	for _, a := range op.Children[7].Children {
		s, _ := a.Value.(string)
		r.Attrs = append(r.Attrs, s)
	}
	return r
}

// ---- test PKI for localhost -----------------------------------------------

type localPKI struct {
	caPEM    string
	otherPEM string // an unrelated CA: the server certificate is untrusted under it
	server   *tls.Config
}

func newLocalPKI(t *testing.T) localPKI {
	t.Helper()
	caCert, caKey, caPEM := newCA(t, "freya ldapdir client test CA")
	_, _, otherPEM := newCA(t, "unrelated CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return localPKI{
		caPEM:    caPEM,
		otherPEM: otherPEM,
		server: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			MinVersion:   tls.VersionTLS12,
		},
	}
}

// ---- client helpers --------------------------------------------------------

// testClient returns a client whose policy allows the given port and whose
// dialer skips the policy Control (loopback is always denied). The returned
// pointer records the timeout the client asked the dialer for.
func testClient(t *testing.T, port int) (*Client, *time.Duration) {
	t.Helper()
	c := NewClient(mustPolicy(t, config.DirectoryTargets{AllowedPorts: []int{port}}))
	var asked time.Duration
	c.dialer = func(timeout time.Duration) *net.Dialer {
		asked = timeout
		return &net.Dialer{Timeout: timeout}
	}
	return c, &asked
}

func localURL(scheme string, port int) string {
	return scheme + "://localhost:" + strconv.Itoa(port)
}

func ctxTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func mustOpen(t *testing.T, c *Client, p ConnParams) Session {
	t.Helper()
	s, err := c.Open(ctxTimeout(t, 5*time.Second), p)
	if err != nil {
		t.Fatalf("Open(%s, %s): %v", p.URL, p.TLSMode, err)
	}
	if s == nil {
		t.Fatal("Open returned a nil session without error")
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// wantClosed asserts err matches want, is sanitised, and did not take long.
func wantClosed(t *testing.T, err, want error, started time.Time, secrets ...string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v (%T), want %v", err, err, want)
	}
	assertSanitised(t, err, secrets...)
	if d := time.Since(started); d > 4*time.Second {
		t.Errorf("took %v; the call must not outlive its deadline", d)
	}
}

// ---- tests -----------------------------------------------------------------

func TestClientImplementsDirectory(t *testing.T) {
	var _ Directory = NewClient(mustPolicy(t, defaultTargets()))
}

func TestBERPacketCapSet(t *testing.T) {
	_ = NewClient(mustPolicy(t, defaultTargets()))
	if MaxBERPacketBytes != 8<<20 {
		t.Fatalf("MaxBERPacketBytes = %d, want 8 MiB (research D7)", MaxBERPacketBytes)
	}
	if ber.MaxPacketLengthBytes != MaxBERPacketBytes {
		t.Fatalf("ber.MaxPacketLengthBytes = %d, want %d", ber.MaxPacketLengthBytes, MaxBERPacketBytes)
	}
}

// The default dialer is the policy dialer, so a hostname that resolves to a
// refused address is caught at connect time (DNS-rebinding safe).
func TestOpenDialsThroughPolicy(t *testing.T) {
	srv := newLDAPServer(t, false, nil, serverScript{})
	c := NewClient(mustPolicy(t, config.DirectoryTargets{AllowedPorts: []int{srv.port}}))

	d := c.dialer(3 * time.Second)
	if d.Control == nil || d.Timeout != 3*time.Second {
		t.Fatalf("default dialer = %+v, want the policy dialer with the requested timeout", d)
	}

	start := time.Now()
	s, err := c.Open(ctxTimeout(t, 5*time.Second), ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain", DialTimeout: 2 * time.Second})
	if s != nil {
		t.Error("Open returned a session for a refused target")
	}
	wantClosed(t, err, ErrTargetRefused, start)
	if n := srv.acceptCount(); n != 0 {
		t.Fatalf("server accepted %d connection(s); the policy must refuse before connect", n)
	}
}

func TestOpenRefusesBeforeDialing(t *testing.T) {
	srv := newLDAPServer(t, false, nil, serverScript{})
	c, _ := testClient(t, srv.port)
	port := strconv.Itoa(srv.port)
	cases := []struct {
		name string
		p    ConnParams
		want error
	}{
		{"literal loopback", ConnParams{URL: "ldap://127.0.0.1:" + port, TLSMode: "plain"}, ErrTargetRefused},
		{"metadata address", ConnParams{URL: "ldap://169.254.169.254:" + port, TLSMode: "plain"}, ErrTargetRefused},
		{"port not allowed", ConnParams{URL: "ldaps://ldap.example.test:636", TLSMode: "ldaps"}, ErrTargetRefused},
		{"userinfo", ConnParams{URL: "ldap://cn=admin:" + passwordSentinel + "@localhost:" + port, TLSMode: "plain"}, ErrInvalidURL},
		{"garbage url", ConnParams{URL: "http://localhost:" + port, TLSMode: "plain"}, ErrInvalidURL},
		{"ldaps url with starttls mode", ConnParams{URL: localURL("ldaps", srv.port), TLSMode: "starttls"}, ErrInvalidURL},
		{"ldaps url with plain mode", ConnParams{URL: localURL("ldaps", srv.port), TLSMode: "plain"}, ErrInvalidURL},
		{"ldap url with ldaps mode", ConnParams{URL: localURL("ldap", srv.port), TLSMode: "ldaps"}, ErrInvalidURL},
		{"unknown tls mode", ConnParams{URL: localURL("ldap", srv.port), TLSMode: "none"}, ErrInvalidURL},
		{"empty tls mode", ConnParams{URL: localURL("ldap", srv.port)}, ErrInvalidURL},
		{"invalid CA", ConnParams{URL: localURL("ldaps", srv.port), TLSMode: "ldaps", CAPEM: "not a pem"}, ErrInvalidCA},
		{"invalid CA with starttls", ConnParams{URL: localURL("ldap", srv.port), TLSMode: "starttls", CAPEM: "not a pem"}, ErrInvalidCA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			s, err := c.Open(ctxTimeout(t, 5*time.Second), tc.p)
			if s != nil {
				t.Error("Open returned a session")
			}
			wantClosed(t, err, tc.want, start)
		})
	}
	if n := srv.acceptCount(); n != 0 {
		t.Fatalf("server accepted %d connection(s); validation must happen before dialing", n)
	}
}

func TestOpenClosedPortIsUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	c, _ := testClient(t, port)
	for _, mode := range []struct{ scheme, tls string }{{"ldap", "plain"}, {"ldap", "starttls"}, {"ldaps", "ldaps"}} {
		start := time.Now()
		s, err := c.Open(ctxTimeout(t, 5*time.Second), ConnParams{URL: localURL(mode.scheme, port), TLSMode: mode.tls, DialTimeout: 2 * time.Second})
		if s != nil {
			t.Errorf("%s: Open returned a session", mode.tls)
		}
		wantClosed(t, err, ErrUnreachable, start, strconv.Itoa(port))
	}
}

func TestOpenDialTimeout(t *testing.T) {
	t.Run("dialer deadline", func(t *testing.T) {
		c, _ := testClient(t, 636)
		c.dialer = func(time.Duration) *net.Dialer {
			return &net.Dialer{Deadline: time.Now().Add(-time.Second)} // already expired
		}
		start := time.Now()
		_, err := c.Open(ctxTimeout(t, 5*time.Second), ConnParams{URL: "ldaps://localhost:636", TLSMode: "ldaps"})
		wantClosed(t, err, ErrTimeout, start)
	})

	t.Run("silent ldaps peer", func(t *testing.T) {
		// Accepts TCP but never completes the TLS handshake.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		var held []net.Conn
		t.Cleanup(func() {
			_ = ln.Close()
			mu.Lock()
			defer mu.Unlock()
			for _, c := range held {
				_ = c.Close()
			}
		})
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				held = append(held, conn)
				mu.Unlock()
			}
		}()
		port := ln.Addr().(*net.TCPAddr).Port
		c, asked := testClient(t, port)
		start := time.Now()
		_, err = c.Open(ctxTimeout(t, 10*time.Second), ConnParams{URL: localURL("ldaps", port), TLSMode: "ldaps", DialTimeout: 300 * time.Millisecond})
		if *asked != 300*time.Millisecond {
			t.Errorf("dialer asked for timeout %v, want ConnParams.DialTimeout", *asked)
		}
		wantClosed(t, err, ErrTimeout, start)
	})
}

func TestOpenDefaultDialTimeout(t *testing.T) {
	pki := newLocalPKI(t)
	srv := newLDAPServer(t, true, pki.server, serverScript{})
	c, asked := testClient(t, srv.port)
	mustOpen(t, c, ConnParams{URL: localURL("ldaps", srv.port), TLSMode: "ldaps", CAPEM: pki.caPEM})
	if *asked != DefaultDialTimeout || DefaultDialTimeout != 5*time.Second {
		t.Fatalf("dial timeout = %v (DefaultDialTimeout %v), want 5s when unset", *asked, DefaultDialTimeout)
	}
}

func TestOpenLDAPS(t *testing.T) {
	pki := newLocalPKI(t)
	srv := newLDAPServer(t, true, pki.server, serverScript{})
	c, _ := testClient(t, srv.port)

	t.Run("trusted CA", func(t *testing.T) {
		s := mustOpen(t, c, ConnParams{URL: localURL("ldaps", srv.port), TLSMode: "ldaps", CAPEM: pki.caPEM})
		st, ok := s.TLSState()
		if !ok || !st.HandshakeComplete {
			t.Fatal("TLSState reports no TLS on an ldaps session")
		}
		if st.Version != tls.VersionTLS13 {
			t.Errorf("negotiated %x, want TLS 1.3 by default", st.Version)
		}
		if len(st.PeerCertificates) == 0 || st.PeerCertificates[0].Subject.CommonName != "localhost" {
			t.Errorf("peer certificate not exposed in TLSState")
		}
	})

	t.Run("untrusted certificate", func(t *testing.T) {
		start := time.Now()
		s, err := c.Open(ctxTimeout(t, 5*time.Second), ConnParams{URL: localURL("ldaps", srv.port), TLSMode: "ldaps", CAPEM: pki.otherPEM})
		if s != nil {
			t.Error("Open returned a session over an untrusted certificate")
		}
		wantClosed(t, err, ErrTLS, start)
	})

	t.Run("system roots do not trust a private CA", func(t *testing.T) {
		start := time.Now()
		_, err := c.Open(ctxTimeout(t, 5*time.Second), ConnParams{URL: localURL("ldaps", srv.port), TLSMode: "ldaps"})
		wantClosed(t, err, ErrTLS, start)
	})
}

func TestOpenLDAPSAgainstTLS12OnlyServer(t *testing.T) {
	pki := newLocalPKI(t)
	cfg := pki.server.Clone()
	cfg.MaxVersion = tls.VersionTLS12
	srv := newLDAPServer(t, true, cfg, serverScript{})
	c, _ := testClient(t, srv.port)

	start := time.Now()
	_, err := c.Open(ctxTimeout(t, 5*time.Second), ConnParams{URL: localURL("ldaps", srv.port), TLSMode: "ldaps", CAPEM: pki.caPEM})
	wantClosed(t, err, ErrTLS, start)

	s := mustOpen(t, c, ConnParams{URL: localURL("ldaps", srv.port), TLSMode: "ldaps", CAPEM: pki.caPEM, AllowTLS12: true})
	if st, ok := s.TLSState(); !ok || st.Version != tls.VersionTLS12 {
		t.Fatalf("AllowTLS12 session: ok=%v version=%x, want TLS 1.2", ok, st.Version)
	}
}

func TestOpenStartTLS(t *testing.T) {
	pki := newLocalPKI(t)
	srv := newLDAPServer(t, false, pki.server, serverScript{})
	c, _ := testClient(t, srv.port)

	s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "starttls", CAPEM: pki.caPEM})
	if st, ok := s.TLSState(); !ok || st.Version != tls.VersionTLS13 {
		t.Fatalf("StartTLS session: ok=%v version=%x, want TLS 1.3", ok, st.Version)
	}
	if err := s.Bind(ctxTimeout(t, 5*time.Second), "cn=svc,dc=example,dc=test", []byte(passwordSentinel)); err != nil {
		t.Fatalf("Bind after StartTLS: %v", err)
	}
	ops := srv.recorded()
	if len(ops) < 2 || ops[0].Tag != ldap.ApplicationExtendedRequest || ops[0].ExtName != startTLSOID {
		t.Fatalf("first operation must be StartTLS, got %+v", ops)
	}
	for _, op := range srv.opsWithTag(ldap.ApplicationBindRequest) {
		if !op.OverTLS {
			t.Fatal("bind was sent before TLS was established")
		}
	}
}

// A failed StartTLS aborts the session; nothing else, in particular no bind,
// is ever sent in plaintext.
func TestOpenStartTLSNeverFallsBack(t *testing.T) {
	pki := newLocalPKI(t)
	cases := []struct {
		name   string
		code   int
		caPEM  string
		want   error
		budget time.Duration
	}{
		{"server refuses (protocolError)", ldap.LDAPResultProtocolError, pki.caPEM, ErrTLS, 5 * time.Second},
		{"server refuses (unavailable)", ldap.LDAPResultUnavailable, pki.caPEM, ErrTLS, 5 * time.Second},
		{"untrusted certificate after accept", 0, pki.otherPEM, ErrTLS, 5 * time.Second},
		{"server never answers", hang, pki.caPEM, ErrTimeout, 300 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newLDAPServer(t, false, pki.server, serverScript{startTLS: tc.code, diag: diagSentinel})
			c, _ := testClient(t, srv.port)
			start := time.Now()
			s, err := c.Open(ctxTimeout(t, tc.budget), ConnParams{URL: localURL("ldap", srv.port), TLSMode: "starttls", CAPEM: tc.caPEM})
			if s != nil {
				_ = s.Bind(context.Background(), "cn=svc", []byte(passwordSentinel))
				t.Fatal("Open returned a session after a failed StartTLS")
			}
			wantClosed(t, err, tc.want, start)
			time.Sleep(50 * time.Millisecond) // let any stray request reach the server
			for _, op := range srv.recorded() {
				if op.Tag != ldap.ApplicationExtendedRequest && op.Tag != ldap.ApplicationUnbindRequest && op.Tag != ldap.ApplicationAbandonRequest {
					t.Fatalf("operation %d sent after StartTLS failed: %+v", op.Tag, op)
				}
			}
		})
	}
}

func TestPlainSessionHasNoTLSState(t *testing.T) {
	srv := newLDAPServer(t, false, nil, serverScript{})
	c, _ := testClient(t, srv.port)
	s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
	if _, ok := s.TLSState(); ok {
		t.Fatal("plain session reports TLS")
	}
	if n := len(srv.opsWithTag(ldap.ApplicationExtendedRequest)); n != 0 {
		t.Fatalf("plain mode sent %d extended request(s)", n)
	}
}

func TestBind(t *testing.T) {
	const dn = "cn=svc,ou=system,dc=example,dc=test"

	t.Run("success sends a simple bind", func(t *testing.T) {
		srv := newLDAPServer(t, false, nil, serverScript{})
		c, _ := testClient(t, srv.port)
		s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
		if err := s.Bind(ctxTimeout(t, 5*time.Second), dn, []byte(passwordSentinel)); err != nil {
			t.Fatalf("Bind: %v", err)
		}
		binds := srv.opsWithTag(ldap.ApplicationBindRequest)
		if len(binds) != 1 || binds[0].BindDN != dn || binds[0].Password != passwordSentinel {
			t.Fatalf("server saw binds %+v", binds)
		}
	})

	t.Run("empty password is refused without a request", func(t *testing.T) {
		srv := newLDAPServer(t, false, nil, serverScript{})
		c, _ := testClient(t, srv.port)
		s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
		for _, pw := range [][]byte{nil, {}} {
			start := time.Now()
			wantClosed(t, s.Bind(ctxTimeout(t, 5*time.Second), dn, pw), ErrInvalidCredentials, start)
		}
		if n := len(srv.opsWithTag(ldap.ApplicationBindRequest)); n != 0 {
			t.Fatalf("an unauthenticated bind reached the server (%d request(s))", n)
		}
	})

	codes := []struct {
		code int
		want error
	}{
		{ldap.LDAPResultInvalidCredentials, ErrInvalidCredentials},
		{ldap.LDAPResultInappropriateAuthentication, ErrDirectory},
		{ldap.LDAPResultUnwillingToPerform, ErrDirectory},
		{ldap.LDAPResultBusy, ErrDirectory},
	}
	for _, tc := range codes {
		t.Run("code "+strconv.Itoa(tc.code), func(t *testing.T) {
			// The diagnostic echoes the password, as some servers do.
			srv := newLDAPServer(t, false, nil, serverScript{bind: tc.code, diag: diagSentinel + " " + passwordSentinel + " " + dn})
			c, _ := testClient(t, srv.port)
			s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
			start := time.Now()
			err := s.Bind(ctxTimeout(t, 5*time.Second), dn, []byte(passwordSentinel))
			wantClosed(t, err, tc.want, start, dn)
			if tc.want == ErrDirectory {
				var de *DirectoryError
				if !errors.As(err, &de) || de.Code != tc.code {
					t.Fatalf("err = %#v, want DirectoryError{Code: %d}", err, tc.code)
				}
			}
		})
	}

	t.Run("server never answers", func(t *testing.T) {
		srv := newLDAPServer(t, false, nil, serverScript{bind: hang})
		c, _ := testClient(t, srv.port)
		s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
		start := time.Now()
		wantClosed(t, s.Bind(ctxTimeout(t, 300*time.Millisecond), dn, []byte(passwordSentinel)), ErrTimeout, start)
	})
}

func TestBaseExists(t *testing.T) {
	const base = "ou=people,dc=example,dc=test"
	cases := []struct {
		name  string
		reply searchReply
		want  error
	}{
		{"present", searchReply{entries: []testEntry{{dn: base}}}, nil},
		{"no such object", searchReply{code: ldap.LDAPResultNoSuchObject}, ErrBaseNotFound},
		{"empty success", searchReply{}, ErrBaseNotFound},
		{"insufficient access", searchReply{code: ldap.LDAPResultInsufficientAccessRights}, ErrDirectory},
		{"time limit", searchReply{code: ldap.LDAPResultTimeLimitExceeded}, ErrTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newLDAPServer(t, false, nil, serverScript{diag: diagSentinel, search: func(searchReq) searchReply { return tc.reply }})
			c, _ := testClient(t, srv.port)
			s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
			start := time.Now()
			err := s.BaseExists(ctxTimeout(t, 5*time.Second), base)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("BaseExists: %v", err)
				}
			} else {
				wantClosed(t, err, tc.want, start)
			}
			reqs := srv.opsWithTag(ldap.ApplicationSearchRequest)
			if len(reqs) != 1 {
				t.Fatalf("want exactly one search, got %d", len(reqs))
			}
			r := reqs[0].Search
			if r.Base != base || r.Scope != ldap.ScopeBaseObject || r.Deref != ldap.NeverDerefAliases {
				t.Errorf("BaseExists sent %+v, want a base-scope search on %q without alias dereferencing", r, base)
			}
		})
	}
}

func TestSearchRequestShape(t *testing.T) {
	var got searchReq
	srv := newLDAPServer(t, false, nil, serverScript{search: func(r searchReq) searchReply { got = r; return searchReply{} }})
	c, _ := testClient(t, srv.port)
	s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})

	attrs := []string{"entryUUID", "mail", "displayName", "givenName", "sn"}
	for _, tc := range []struct {
		scope Scope
		wire  int64
	}{{ScopeSub, ldap.ScopeWholeSubtree}, {ScopeOne, ldap.ScopeSingleLevel}} {
		q := Query{
			BaseDN:     "ou=people,dc=example,dc=test",
			Scope:      tc.scope,
			Filter:     "(&(objectClass=person)(mail=*))",
			Attributes: attrs,
			SizeLimit:  500,
			TimeLimit:  15 * time.Second,
		}
		page, err := s.Search(ctxTimeout(t, 5*time.Second), q)
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		if page.Truncated || len(page.Entries) != 0 || page.Referrals != 0 {
			t.Errorf("empty result reported as %+v", page)
		}
		want := searchReq{
			Base: q.BaseDN, Scope: tc.wire, Deref: ldap.NeverDerefAliases,
			SizeLimit: 501, // SizeLimit+1 so truncation is detectable
			TimeLimit: 15, TypesOnly: false, Filter: q.Filter, Attrs: attrs,
		}
		if got.Base != want.Base || got.Scope != want.Scope || got.Deref != want.Deref || got.SizeLimit != want.SizeLimit ||
			got.TimeLimit != want.TimeLimit || got.TypesOnly || got.Filter != want.Filter || strings.Join(got.Attrs, ",") != strings.Join(want.Attrs, ",") {
			t.Errorf("server saw %+v\nwant          %+v", got, want)
		}
	}

	// An empty attribute list would mean "all user attributes"; it is refused.
	start := time.Now()
	_, err := s.Search(ctxTimeout(t, 5*time.Second), Query{BaseDN: "dc=example,dc=test", Filter: "(objectClass=*)", SizeLimit: 1, TimeLimit: time.Second})
	if err == nil {
		t.Fatal("Search with no attributes must be refused")
	}
	assertSanitised(t, err)
	if time.Since(start) > 4*time.Second {
		t.Error("refusal took too long")
	}
	if n := len(srv.opsWithTag(ldap.ApplicationSearchRequest)); n != 2 {
		t.Fatalf("server saw %d searches, want 2 (the attribute-less one must not be sent)", n)
	}
}

func TestSearchEntriesAndReferrals(t *testing.T) {
	entries := []testEntry{
		{dn: "uid=ann,ou=people,dc=example,dc=test", attrs: map[string][]string{"Mail": {"ann@example.test"}, "cn": {"Ann", "Annie"}}},
		{dn: "uid=bob,ou=people,dc=example,dc=test", attrs: map[string][]string{"mail": {"bob@example.test"}}},
	}
	srv := newLDAPServer(t, false, nil, serverScript{search: func(searchReq) searchReply {
		return searchReply{entries: entries, refs: []string{"ldap://other.example.test/dc=x", "ldap://third.example.test/dc=y"}}
	}})
	c, _ := testClient(t, srv.port)
	s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
	page, err := s.Search(ctxTimeout(t, 5*time.Second), Query{BaseDN: "ou=people,dc=example,dc=test", Filter: "(objectClass=*)", Attributes: []string{"mail", "cn"}, SizeLimit: 10, TimeLimit: 5 * time.Second})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if page.Truncated || page.Referrals != 2 || len(page.Entries) != 2 {
		t.Fatalf("page = %+v, want 2 entries, 2 referrals counted, not truncated", page)
	}
	e := page.Entries[0]
	if e.DN != entries[0].dn {
		t.Errorf("DN = %q", e.DN)
	}
	// Attribute names are case-insensitive in LDAP; keys are lower-cased.
	if got := e.Attrs["mail"]; len(got) != 1 || string(got[0]) != "ann@example.test" {
		t.Errorf("mail = %q", got)
	}
	if got := e.Attrs["cn"]; len(got) != 2 || string(got[0]) != "Ann" || string(got[1]) != "Annie" {
		t.Errorf("cn = %q", got)
	}
	if _, ok := e.Attrs["Mail"]; ok {
		t.Error("attribute keys must be lower-cased")
	}
	// Referrals are counted, never followed: one search, one connection.
	if n := len(srv.opsWithTag(ldap.ApplicationSearchRequest)); n != 1 || srv.acceptCount() != 1 {
		t.Fatalf("searches=%d connections=%d; referrals must not be chased", n, srv.acceptCount())
	}
}

func manyEntries(n int) []testEntry {
	out := make([]testEntry, n)
	for i := range out {
		out[i] = testEntry{dn: "uid=u" + strconv.Itoa(i) + ",dc=example,dc=test", attrs: map[string][]string{"mail": {"u" + strconv.Itoa(i) + "@example.test"}}}
	}
	return out
}

func TestSearchTruncation(t *testing.T) {
	const limit = 3
	cases := []struct {
		name  string
		reply searchReply
		want  int
	}{
		{"exactly the limit", searchReply{entries: manyEntries(limit)}, limit},
		{"limit+1 means truncated", searchReply{entries: manyEntries(limit + 1)}, limit},
		{"server ignores the limit", searchReply{entries: manyEntries(limit + 20)}, limit},
		{"4 sizeLimitExceeded", searchReply{entries: manyEntries(2), code: ldap.LDAPResultSizeLimitExceeded}, 2},
		{"3 timeLimitExceeded", searchReply{entries: manyEntries(1), code: ldap.LDAPResultTimeLimitExceeded}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newLDAPServer(t, false, nil, serverScript{diag: diagSentinel, search: func(searchReq) searchReply { return tc.reply }})
			c, _ := testClient(t, srv.port)
			s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
			page, err := s.Search(ctxTimeout(t, 5*time.Second), Query{BaseDN: "dc=example,dc=test", Filter: "(objectClass=*)", Attributes: []string{"mail"}, SizeLimit: limit, TimeLimit: 5 * time.Second})
			if err != nil {
				t.Fatalf("Search: %v (size/time limits are a truncated result, not an error)", err)
			}
			if len(page.Entries) != tc.want {
				t.Errorf("got %d entries, want %d", len(page.Entries), tc.want)
			}
			wantTrunc := tc.name != "exactly the limit"
			if page.Truncated != wantTrunc {
				t.Errorf("Truncated = %v, want %v", page.Truncated, wantTrunc)
			}
		})
	}
}

func TestSearchErrors(t *testing.T) {
	cases := []struct {
		name  string
		reply searchReply
		want  error
		code  int
	}{
		{"32 base not found", searchReply{code: ldap.LDAPResultNoSuchObject}, ErrBaseNotFound, 0},
		{"50 insufficient access", searchReply{code: ldap.LDAPResultInsufficientAccessRights}, ErrDirectory, ldap.LDAPResultInsufficientAccessRights},
		{"10 referral is not followed", searchReply{code: ldap.LDAPResultReferral}, ErrDirectory, ldap.LDAPResultReferral},
		{"53 unwilling", searchReply{code: ldap.LDAPResultUnwillingToPerform}, ErrDirectory, ldap.LDAPResultUnwillingToPerform},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newLDAPServer(t, false, nil, serverScript{diag: diagSentinel + " " + passwordSentinel, search: func(searchReq) searchReply { return tc.reply }})
			c, _ := testClient(t, srv.port)
			s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
			start := time.Now()
			_, err := s.Search(ctxTimeout(t, 5*time.Second), Query{BaseDN: "dc=example,dc=test", Filter: "(objectClass=*)", Attributes: []string{"mail"}, SizeLimit: 5, TimeLimit: 5 * time.Second})
			wantClosed(t, err, tc.want, start)
			if tc.code != 0 {
				var de *DirectoryError
				if !errors.As(err, &de) || de.Code != tc.code {
					t.Fatalf("err = %#v, want DirectoryError{Code: %d}", err, tc.code)
				}
			}
		})
	}

	t.Run("server never answers", func(t *testing.T) {
		srv := newLDAPServer(t, false, nil, serverScript{search: func(searchReq) searchReply { return searchReply{code: hang} }})
		c, _ := testClient(t, srv.port)
		s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
		start := time.Now()
		_, err := s.Search(ctxTimeout(t, 300*time.Millisecond), Query{BaseDN: "dc=example,dc=test", Filter: "(objectClass=*)", Attributes: []string{"mail"}, SizeLimit: 5, TimeLimit: 30 * time.Second})
		wantClosed(t, err, ErrTimeout, start)
	})

	t.Run("oversized BER packet is refused", func(t *testing.T) {
		// A SEQUENCE header announcing 9 MiB: over the cap, so the client must
		// fail at once instead of waiting to buffer it.
		n := 9 << 20
		raw := []byte{0x30, 0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n), 0x02, 0x01, 0x02}
		srv := newLDAPServer(t, false, nil, serverScript{search: func(searchReq) searchReply { return searchReply{raw: raw} }})
		c, _ := testClient(t, srv.port)
		s := mustOpen(t, c, ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
		start := time.Now()
		page, err := s.Search(ctxTimeout(t, 3*time.Second), Query{BaseDN: "dc=example,dc=test", Filter: "(objectClass=*)", Attributes: []string{"mail"}, SizeLimit: 5, TimeLimit: 30 * time.Second})
		if err == nil || errors.Is(err, ErrTimeout) {
			t.Fatalf("err = %v, want an immediate closed error (not a timeout)", err)
		}
		assertSanitised(t, err)
		if len(page.Entries) != 0 {
			t.Errorf("entries returned from a refused packet: %+v", page)
		}
		if time.Since(start) > 2*time.Second {
			t.Error("oversized packet was not refused promptly")
		}
	})
}

func TestSessionClose(t *testing.T) {
	srv := newLDAPServer(t, false, nil, serverScript{})
	c, _ := testClient(t, srv.port)
	s, err := c.Open(ctxTimeout(t, 5*time.Second), ConnParams{URL: localURL("ldap", srv.port), TLSMode: "plain"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	start := time.Now()
	_, err = s.Search(ctxTimeout(t, 2*time.Second), Query{BaseDN: "dc=example,dc=test", Filter: "(objectClass=*)", Attributes: []string{"mail"}, SizeLimit: 1, TimeLimit: time.Second})
	wantClosed(t, err, ErrUnreachable, start)
}
