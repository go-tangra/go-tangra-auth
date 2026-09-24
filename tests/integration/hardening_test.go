//go:build integration

package integration

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/transport/edge"
)

// TestHardening sweeps the edge beyond the stories: body/header limits,
// per-route bursts with spoofed origins, TLS 1.2 and plaintext refusal, and
// security headers on every kind of route.
func TestHardening(t *testing.T) {
	e := Start(t)
	e.Seed("acme", "alice@acme.test", pw, "")
	host := strings.TrimPrefix(e.Base, "https://")
	// Oversized body and oversized headers are refused before any handler.
	big := strings.NewReader(`{"tenant":"acme","email":"a@x","password":"` + strings.Repeat("x", 2<<20) + `"}`)
	req, _ := http.NewRequest(http.MethodPost, e.Base+"/api/v1/signin", big)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(edge.CSRFHeader, e.CSRF()) // past the CSRF filter: the body limit must refuse
	req.Header.Set("Origin", e.Base)
	resp, err := e.Client.Do(req)
	if err == nil {
		if resp.StatusCode != 413 && resp.StatusCode != 400 {
			t.Errorf("oversized body → %d", resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
	req, _ = http.NewRequest(http.MethodGet, e.Base+"/api/v1/session", nil)
	req.Header.Set("X-Padding", strings.Repeat("p", 512<<10))
	if resp, err := e.Client.Do(req); err == nil {
		if resp.StatusCode != 431 && resp.StatusCode != 400 {
			t.Errorf("oversized headers → %d", resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
	// Per-route burst: spoofed X-Forwarded-For from an untrusted client must
	// not open a fresh bucket.
	limited := false
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest(http.MethodGet, e.Base+"/api/v1/tenants/resolve?slug=acme", nil)
		req.Header.Set("X-Forwarded-For", "198.51.100."+string(rune('1'+i%9)))
		resp, err := e.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == 429 {
			limited = true
			if resp.Header.Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
			break
		}
	}
	if !limited {
		t.Error("per-route burst was not limited despite spoofed X-Forwarded-For")
	}
	// TLS 1.2 is refused at the handshake; plaintext gets no HTTP service.
	d := &net.Dialer{Timeout: 5 * time.Second}
	if conn, err := tls.DialWithDialer(d, "tcp", host, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}); err == nil { //nolint:gosec // probing our own listener
		_ = conn.Close()
		t.Error("TLS 1.2 handshake accepted")
	}
	if raw, err := net.DialTimeout("tcp", host, 5*time.Second); err == nil {
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = raw.Write([]byte("GET /api/v1/session HTTP/1.1\r\nHost: x\r\n\r\n"))
		buf := make([]byte, 64)
		n, _ := raw.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "HTTP/1.1 200") {
			t.Error("plaintext request served")
		}
		_ = raw.Close()
	}
	// Security headers on the console, the API and error responses.
	for _, path := range []string{"/console/signin", "/api/v1/session", "/api/v1/nope", "/.well-known/jwks.json"} {
		resp, err := e.Client.Get(e.Base + path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		for _, h := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options"} {
			if resp.Header.Get(h) == "" {
				t.Errorf("%s: missing %s", path, h)
			}
		}
		if strings.Contains(resp.Header.Get("Content-Security-Policy"), "unsafe-inline") && path == "/console/signin" {
			t.Errorf("%s: CSP allows unsafe-inline", path)
		}
	}
}
