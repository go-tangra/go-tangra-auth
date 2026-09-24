package ldapdir

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ErrInvalidCA means the connection's CA PEM is oversized, holds no
// certificate, or contains anything that is not a parseable certificate.
var ErrInvalidCA = errors.New("ldapdir: invalid CA certificate bundle")

// MaxCAPEMBytes caps the per-connection CA bundle (research D3).
const MaxCAPEMBytes = 64 << 10

var pemBegin = []byte("-----BEGIN")

// tls12Suites is the approved TLS 1.2 list: ECDHE key exchange with an AEAD
// cipher only. TLS 1.3 suites are fixed by crypto/tls and need no list.
var tls12Suites = [...]uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// ParseCA parses a CA bundle strictly. An empty string returns (nil, nil),
// meaning the system roots. Otherwise every PEM block must be a CERTIFICATE
// that parses, and there must be at least one. Errors never echo the input.
func ParseCA(caPEM string) (*x509.CertPool, error) {
	if caPEM == "" {
		return nil, nil
	}
	if len(caPEM) > MaxCAPEMBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalidCA, MaxCAPEMBytes)
	}
	data := []byte(caPEM)
	// pem.Decode silently skips malformed blocks, so every BEGIN marker must
	// account for exactly one decoded certificate.
	markers := bytes.Count(data, pemBegin)
	pool := x509.NewCertPool()
	certs := 0
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: non-certificate PEM block", ErrInvalidCA)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: unparseable certificate", ErrInvalidCA)
		}
		pool.AddCert(cert)
		certs++
	}
	if certs == 0 {
		return nil, fmt.Errorf("%w: no certificate", ErrInvalidCA)
	}
	if certs != markers {
		return nil, fmt.Errorf("%w: malformed PEM block", ErrInvalidCA)
	}
	return pool, nil
}

// NewTLSConfig builds the client TLS config for one directory connection
// (research D3): ServerName from the validated endpoint, RootCAs from caPEM or
// the system roots, TLS 1.3 minimum unless allowTLS12. Verification is never
// skipped or replaced. Each call returns a fresh config.
func NewTLSConfig(ep Endpoint, caPEM string, allowTLS12 bool) (*tls.Config, error) {
	if ep.Host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrInvalidURL)
	}
	roots, err := ParseCA(caPEM)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		ServerName:    ep.Host,
		RootCAs:       roots,
		MinVersion:    tls.VersionTLS13,
		Renegotiation: tls.RenegotiateNever,
	}
	if allowTLS12 {
		cfg.MinVersion = tls.VersionTLS12
		cfg.CipherSuites = append([]uint16(nil), tls12Suites[:]...)
	}
	return cfg, nil
}
