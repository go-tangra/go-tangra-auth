package ldapdir

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// testPKI is a throwaway CA plus a server certificate it issued.
type testPKI struct {
	caPEM    string
	caCert   *x509.Certificate
	server   tls.Certificate
	keyPEM   string // PEM of the server private key, for the "no certificate" case
	otherPEM string // PEM of an unrelated CA, for the untrusted case
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	caCert, caKey, caPEM := newCA(t, "freya ldapdir test CA")
	_, _, otherPEM := newCA(t, "unrelated CA")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ldap.example.test"},
		DNSNames:     []string{"ldap.example.test"},
		IPAddresses:  []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{
		caPEM:    caPEM,
		caCert:   caCert,
		server:   tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		keyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		otherPEM: otherPEM,
	}
}

func newCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func mustTLSConfig(t *testing.T, ep Endpoint, caPEM string, allowTLS12 bool) *tls.Config {
	t.Helper()
	cfg, err := NewTLSConfig(ep, caPEM, allowTLS12)
	if err != nil {
		t.Fatalf("NewTLSConfig(%+v, allowTLS12=%v): %v", ep, allowTLS12, err)
	}
	if cfg == nil {
		t.Fatal("NewTLSConfig returned nil config without error")
	}
	return cfg
}

var ldapsEP = Endpoint{Scheme: "ldaps", Host: "ldap.example.test", Port: 636}

func TestMaxCAPEMBytes(t *testing.T) {
	if MaxCAPEMBytes != 64<<10 {
		t.Fatalf("MaxCAPEMBytes = %d, want 65536", MaxCAPEMBytes)
	}
}

func TestParseCARejectsInvalid(t *testing.T) {
	pki := newTestPKI(t)
	garbageCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER at all")}))
	cases := map[string]string{
		"too large":                pki.caPEM + strings.Repeat("\n", MaxCAPEMBytes+1-len(pki.caPEM)),
		"way too large":            strings.Repeat(pki.caPEM, (MaxCAPEMBytes/len(pki.caPEM))+2),
		"garbage text":             "this is not a certificate",
		"garbage bytes":            "\x00\x01\x02\xff\xfe",
		"whitespace only":          " \n\t\n",
		"private key only":         pki.keyPEM,
		"cert block with bad DER":  garbageCert,
		"valid cert then bad DER":  pki.caPEM + garbageCert,
		"valid cert plus key":      pki.caPEM + pki.keyPEM,
		"truncated pem":            pki.caPEM[:len(pki.caPEM)/2],
		"public key block":         "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		"begin marker without end": "-----BEGIN CERTIFICATE-----\nMIIB\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			pool, err := ParseCA(in)
			if !errors.Is(err, ErrInvalidCA) {
				t.Fatalf("ParseCA = (%v, %v), want ErrInvalidCA", pool, err)
			}
			if pool != nil {
				t.Fatal("ParseCA returned a pool together with an error")
			}
			// The error text is fixed: it never echoes the submitted PEM.
			if trimmed := strings.TrimSpace(in); len(trimmed) >= 8 && strings.Contains(err.Error(), trimmed[:8]) {
				t.Fatalf("error %q echoes the input", err)
			}
			if _, err := NewTLSConfig(ldapsEP, in, false); !errors.Is(err, ErrInvalidCA) {
				t.Fatalf("NewTLSConfig with invalid CA: err = %v, want ErrInvalidCA", err)
			}
		})
	}
}

func TestParseCAAccepts(t *testing.T) {
	pki := newTestPKI(t)
	serverLeaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.server.Certificate[0]}))
	atLimit := pki.caPEM + strings.Repeat("\n", MaxCAPEMBytes-len(pki.caPEM))
	if len(atLimit) != MaxCAPEMBytes {
		t.Fatalf("fixture length %d", len(atLimit))
	}
	cases := map[string]struct {
		in    string
		certs int
	}{
		"single CA":                  {pki.caPEM, 1},
		"bundle of two":              {pki.caPEM + pki.otherPEM, 2},
		"leading and trailing text":  {"# corporate root\n" + pki.caPEM + "\n# end\n", 1},
		"CRLF line endings":          {strings.ReplaceAll(pki.caPEM, "\n", "\r\n"), 1},
		"exactly at size limit":      {atLimit, 1},
		"self-signed leaf is usable": {serverLeaf, 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			pool, err := ParseCA(tc.in)
			if err != nil {
				t.Fatalf("ParseCA: %v", err)
			}
			if pool == nil {
				t.Fatal("ParseCA returned nil pool for a non-empty bundle")
			}
			//nolint:staticcheck // Subjects is fine for pools built from PEM.
			if got := len(pool.Subjects()); got != tc.certs {
				t.Fatalf("pool has %d certs, want %d", got, tc.certs)
			}
		})
	}
}

func TestParseCAEmptyMeansSystemRoots(t *testing.T) {
	pool, err := ParseCA("")
	if err != nil || pool != nil {
		t.Fatalf("ParseCA(\"\") = (%v, %v), want (nil, nil) = system roots", pool, err)
	}
	cfg := mustTLSConfig(t, ldapsEP, "", false)
	if cfg.RootCAs != nil {
		t.Fatal("empty CA PEM must leave RootCAs nil so the system roots are used")
	}
}

func TestNewTLSConfigUsesCAPool(t *testing.T) {
	pki := newTestPKI(t)
	cfg := mustTLSConfig(t, ldapsEP, pki.caPEM, false)
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil although a CA PEM was given")
	}
	want := x509.NewCertPool()
	want.AddCert(pki.caCert)
	if !cfg.RootCAs.Equal(want) {
		t.Fatal("RootCAs does not hold exactly the connection's CA")
	}
}

func TestNewTLSConfigDefaultsToTLS13(t *testing.T) {
	cfg := mustTLSConfig(t, ldapsEP, "", false)
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %#x, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("MaxVersion = %#x", cfg.MaxVersion)
	}
	// TLS 1.3 suites are not configurable; a list here would only mislead.
	if cfg.CipherSuites != nil {
		t.Fatalf("CipherSuites = %v, want nil under TLS 1.3", cfg.CipherSuites)
	}
}

// approvedTLS12 is the Constitution's approved list: ECDHE key exchange with an
// AEAD cipher, nothing else.
var approvedTLS12 = map[uint16]bool{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       true,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: true,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         true,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         true,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   true,
}

func TestNewTLSConfigAllowTLS12(t *testing.T) {
	cfg := mustTLSConfig(t, ldapsEP, "", true)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want TLS 1.2 with allow_tls12", cfg.MinVersion)
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("MaxVersion = %#x, TLS 1.3 must stay available", cfg.MaxVersion)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Fatal("allow_tls12 must pin an explicit cipher list, not Go's defaults")
	}
	insecure := map[uint16]bool{}
	for _, s := range tls.InsecureCipherSuites() {
		insecure[s.ID] = true
	}
	for _, id := range cfg.CipherSuites {
		name := tls.CipherSuiteName(id)
		if !approvedTLS12[id] || insecure[id] {
			t.Errorf("suite %s is not an approved AEAD ECDHE suite", name)
		}
		if !strings.Contains(name, "ECDHE") || !(strings.Contains(name, "GCM") || strings.Contains(name, "CHACHA20_POLY1305")) {
			t.Errorf("suite %s is not ECDHE+AEAD", name)
		}
	}
}

func TestNewTLSConfigServerName(t *testing.T) {
	cases := map[string]Endpoint{
		"hostname":    {Scheme: "ldaps", Host: "ldap.example.test", Port: 636},
		"starttls":    {Scheme: "ldap", Host: "dc01.corp.example", Port: 389},
		"ipv4":        {Scheme: "ldaps", Host: "192.0.2.10", Port: 636},
		"ipv6":        {Scheme: "ldaps", Host: "2001:db8::10", Port: 636},
		"global cat.": {Scheme: "ldaps", Host: "gc.corp.example", Port: 3269},
	}
	for name, ep := range cases {
		t.Run(name, func(t *testing.T) {
			for _, tls12 := range []bool{false, true} {
				cfg := mustTLSConfig(t, ep, "", tls12)
				if cfg.ServerName != ep.Host {
					t.Fatalf("ServerName = %q, want %q", cfg.ServerName, ep.Host)
				}
			}
		})
	}
}

func TestNewTLSConfigRefusesEmptyHost(t *testing.T) {
	if cfg, err := NewTLSConfig(Endpoint{Scheme: "ldaps", Port: 636}, "", false); err == nil {
		t.Fatalf("NewTLSConfig with empty host = %v, want error (verification needs a name)", cfg)
	}
}

func TestNewTLSConfigNeverSkipsVerification(t *testing.T) {
	pki := newTestPKI(t)
	for _, ca := range []string{"", pki.caPEM} {
		for _, tls12 := range []bool{false, true} {
			cfg := mustTLSConfig(t, ldapsEP, ca, tls12)
			if cfg.InsecureSkipVerify {
				t.Fatalf("InsecureSkipVerify set (ca=%v, tls12=%v)", ca != "", tls12)
			}
			// No hook may replace or weaken the standard chain verification.
			if cfg.VerifyPeerCertificate != nil || cfg.VerifyConnection != nil {
				t.Fatal("custom verification callback installed")
			}
			if cfg.Renegotiation != tls.RenegotiateNever {
				t.Fatalf("Renegotiation = %v, want RenegotiateNever", cfg.Renegotiation)
			}
		}
	}
}

func TestNewTLSConfigReturnsFreshConfig(t *testing.T) {
	a := mustTLSConfig(t, ldapsEP, "", true)
	b := mustTLSConfig(t, ldapsEP, "", true)
	if a == b {
		t.Fatal("configs must not be shared between connections")
	}
	a.CipherSuites[0] = tls.TLS_RSA_WITH_AES_128_CBC_SHA
	c := mustTLSConfig(t, ldapsEP, "", true)
	if !approvedTLS12[c.CipherSuites[0]] {
		t.Fatal("mutating one config changed the package's cipher list")
	}
}

// handshake runs a client handshake with clientCfg against a server that
// presents pki.server and speaks at most serverMax.
func handshake(t *testing.T, pki testPKI, clientCfg *tls.Config, serverMax uint16) (tls.ConnectionState, error) {
	t.Helper()
	cConn, sConn := net.Pipe()
	defer cConn.Close()
	defer sConn.Close()
	srv := tls.Server(sConn, &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   serverMax,
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Handshake()
		_ = sConn.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cli := tls.Client(cConn, clientCfg)
	err := cli.HandshakeContext(ctx)
	_ = cConn.Close()
	<-done
	return cli.ConnectionState(), err
}

func TestHandshakeBehaviour(t *testing.T) {
	pki := newTestPKI(t)

	t.Run("trusted CA over TLS 1.3", func(t *testing.T) {
		st, err := handshake(t, pki, mustTLSConfig(t, ldapsEP, pki.caPEM, false), tls.VersionTLS13)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if st.Version != tls.VersionTLS13 {
			t.Fatalf("negotiated %#x, want TLS 1.3", st.Version)
		}
	})

	t.Run("IP literal verified against SAN", func(t *testing.T) {
		ep := Endpoint{Scheme: "ldaps", Host: "192.0.2.10", Port: 636}
		if _, err := handshake(t, pki, mustTLSConfig(t, ep, pki.caPEM, false), tls.VersionTLS13); err != nil {
			t.Fatalf("handshake: %v", err)
		}
	})

	t.Run("hostname mismatch refused", func(t *testing.T) {
		ep := Endpoint{Scheme: "ldaps", Host: "other.example.test", Port: 636}
		if _, err := handshake(t, pki, mustTLSConfig(t, ep, pki.caPEM, false), tls.VersionTLS13); err == nil {
			t.Fatal("handshake succeeded with a certificate for another name")
		}
	})

	t.Run("untrusted CA refused", func(t *testing.T) {
		if _, err := handshake(t, pki, mustTLSConfig(t, ldapsEP, pki.otherPEM, false), tls.VersionTLS13); err == nil {
			t.Fatal("handshake succeeded with a CA that did not issue the server cert")
		}
	})

	t.Run("system roots do not trust a private CA", func(t *testing.T) {
		if _, err := handshake(t, pki, mustTLSConfig(t, ldapsEP, "", false), tls.VersionTLS13); err == nil {
			t.Fatal("handshake succeeded against a private CA with system roots")
		}
	})

	t.Run("TLS 1.2 server refused by default", func(t *testing.T) {
		if _, err := handshake(t, pki, mustTLSConfig(t, ldapsEP, pki.caPEM, false), tls.VersionTLS12); err == nil {
			t.Fatal("TLS 1.2 negotiated without allow_tls12")
		}
	})

	t.Run("TLS 1.2 server accepted with allow_tls12", func(t *testing.T) {
		st, err := handshake(t, pki, mustTLSConfig(t, ldapsEP, pki.caPEM, true), tls.VersionTLS12)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if st.Version != tls.VersionTLS12 || !approvedTLS12[st.CipherSuite] {
			t.Fatalf("negotiated %#x/%s", st.Version, tls.CipherSuiteName(st.CipherSuite))
		}
	})

	t.Run("allow_tls12 still prefers TLS 1.3", func(t *testing.T) {
		st, err := handshake(t, pki, mustTLSConfig(t, ldapsEP, pki.caPEM, true), tls.VersionTLS13)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if st.Version != tls.VersionTLS13 {
			t.Fatalf("negotiated %#x, want TLS 1.3", st.Version)
		}
	})
}
