//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/config"
)

// TestWebAuthnPlaywright (feature 018, T026) runs the console Playwright
// scenario console/tests/e2e/webauthn.spec.ts against this service with the
// Chrome DevTools virtual authenticator. Browsers only allow security keys in
// a secure context without certificate errors and never for IP addresses, so
// the console is served by the Vite dev server on http://localhost (a secure
// context) which proxies /api to the harness edge (presenting the edge's
// origin, AUTH_EDGE_URL in vite.config.ts); the relying party is "localhost"
// with the browser's origin.
//
// It needs Node, the console dependencies and a Chromium (PW_CHANNEL=chrome
// for the system Chrome), so it only runs when E2E_PLAYWRIGHT=1.
func TestWebAuthnPlaywright(t *testing.T) {
	if os.Getenv("E2E_PLAYWRIGHT") != "1" {
		t.Skip("set E2E_PLAYWRIGHT=1 to run the console security-key scenario")
	}
	port := freeLocalPort(t)
	origin := "http://localhost:" + port
	on := true
	e := Start(t, func(c *config.Config, _ string) {
		c.WebAuthn.Enabled, c.WebAuthn.RPID, c.WebAuthn.Origins = &on, "localhost", []string{origin}
	})
	const tenant, em, pw = "keys", "keys@keys.test", "keys-password-1"
	tid, _ := e.Seed(tenant, em, pw, "")

	consoleDir, err := filepath.Abs("../../console")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vite := exec.CommandContext(ctx, "npx", "vite", "--host", "localhost", "--port", port, "--strictPort")
	vite.Dir = consoleDir
	vite.Env = append(os.Environ(), "AUTH_EDGE_URL="+e.Base)
	vite.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	vite.Cancel = func() error { return syscall.Kill(-vite.Process.Pid, syscall.SIGTERM) }
	vite.Stdout, vite.Stderr = os.Stderr, os.Stderr
	if err := vite.Start(); err != nil {
		t.Fatalf("vite: %v", err)
	}
	defer func() { cancel(); _ = vite.Wait() }()
	waitHTTP(t, origin+"/console/signin")

	pwt := exec.CommandContext(ctx, "npx", "playwright", "test", "tests/e2e/webauthn.spec.ts", "--reporter=list")
	pwt.Dir = consoleDir
	pwt.Env = append(os.Environ(), "AUTH_BASE_URL="+origin, "E2E_KEY_TENANT="+tenant, "E2E_KEY_EMAIL="+em, "E2E_KEY_PASSWORD="+pw)
	pwt.Stdout, pwt.Stderr = os.Stderr, os.Stderr
	if err := pwt.Run(); err != nil {
		t.Fatalf("playwright: %v", err)
	}
	// The browser ceremonies reached the service: enrolment, sign-in with a
	// hardware key and removal are audited.
	for _, ev := range []string{"mfa_enrolled", "mfa_removed"} {
		if n := e.AuditCount(tid, ev); n != 1 {
			t.Errorf("audit %s = %d, want 1", ev, n)
		}
	}
}

func freeLocalPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
}

func waitHTTP(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if res, err := http.Get(url); err == nil { //nolint:gosec,noctx // local dev server
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("%s did not come up", url)
}
