//go:build integration

// Package integration boots the service in-process against real TimescaleDB,
// Valkey (TLS), OpenFGA and Mailpit containers.
package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-auth/v4/internal/app"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/config"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra/v4"
	fconfig "github.com/go-tangra/go-tangra/v4/config"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

// Env is a running service plus helpers.
type Env struct {
	T      *testing.T
	App    *app.App
	Base   string // https://127.0.0.1:port
	Mail   string // mailpit API base
	Client *http.Client
	Cancel context.CancelFunc
	PGIP   string // TimescaleDB container address on the docker network
}

func container(t *testing.T, req testcontainers.ContainerRequest) (c testcontainers.Container, host string, ports map[string]string) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		t.Skipf("testcontainers unavailable (%s): %v", req.Image, err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, _ = c.Host(ctx)
	ports = map[string]string{}
	for _, p := range req.ExposedPorts {
		mp, err := c.MappedPort(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		ports[p] = mp.Port()
	}
	return c, host, ports
}

// selfSigned writes a server certificate for the Valkey container.
func selfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "valkey"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, DNSNames: []string{"localhost"}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath = filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o644)
	return
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

// Start boots every dependency and the service; skips when Docker is absent.
// mutate hooks run after the containers are up and before the app is built;
// they receive the TimescaleDB container's docker-network address (for
// directory target-policy CIDRs).
func Start(t *testing.T, mutate ...func(*config.Config, string)) *Env {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	pgC, pgHost, pgPorts := container(t, testcontainers.ContainerRequest{Image: "timescale/timescaledb:latest-pg16", ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{"POSTGRES_PASSWORD": "test", "POSTGRES_DB": "auth"}, WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(2 * time.Minute)})
	pgIP, err := pgC.ContainerIP(ctx)
	if err != nil {
		t.Fatalf("timescaledb container address: %v", err)
	}
	adminDSN := fmt.Sprintf("postgres://postgres:test@%s:%s/auth?sslmode=disable", pgHost, pgPorts["5432/tcp"])
	for i := 0; i < 30; i++ {
		conn, err := pgx.Connect(ctx, adminDSN)
		if err == nil {
			_, _ = conn.Exec(ctx, "CREATE ROLE auth_app LOGIN PASSWORD 'app' NOBYPASSRLS")
			_ = conn.Close(ctx)
			break
		}
		time.Sleep(time.Second)
	}
	certPath, keyPath := selfSigned(t, dir)
	_, vkHost, vkPorts := container(t, testcontainers.ContainerRequest{Image: "valkey/valkey:8", ExposedPorts: []string{"6379/tcp"},
		Files:      []testcontainers.ContainerFile{{HostFilePath: certPath, ContainerFilePath: "/tls/server.crt", FileMode: 0o644}, {HostFilePath: keyPath, ContainerFilePath: "/tls/server.key", FileMode: 0o644}},
		Cmd:        []string{"valkey-server", "--tls-port", "6379", "--port", "0", "--tls-cert-file", "/tls/server.crt", "--tls-key-file", "/tls/server.key", "--tls-ca-cert-file", "/tls/server.crt", "--tls-auth-clients", "no", "--requirepass", "test"},
		WaitingFor: wait.ForListeningPort("6379/tcp")})
	_, fgaHost, fgaPorts := container(t, testcontainers.ContainerRequest{Image: "openfga/openfga:v1.20.0", ExposedPorts: []string{"8080/tcp"},
		Cmd: []string{"run", "--authn-method=preshared", "--authn-preshared-keys=test-key", "--playground-enabled=false"}, WaitingFor: wait.ForHTTP("/healthz").WithPort("8080/tcp")})
	_, mpHost, mpPorts := container(t, testcontainers.ContainerRequest{Image: "axllent/mailpit:latest", ExposedPorts: []string{"1025/tcp", "8025/tcp"}, WaitingFor: wait.ForListeningPort("8025/tcp")})
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	kekPath := filepath.Join(dir, "kek.b64")
	_ = os.WriteFile(kekPath, []byte(base64.StdEncoding.EncodeToString(kek)), 0o600)
	edgeAddr := freePort(t)

	cfg := config.Default()
	cfg.ServiceName, cfg.TrustDomain, cfg.Env = "auth", "example.org", "test"
	cfg.Server.GRPCAddr, cfg.Admin.Addr = "127.0.0.1:0", "127.0.0.1:0"
	cfg.Authz = fconfig.Authz{Source: fconfig.AuthzFile, Path: "../../deploy/policy.yaml"}
	cfg.Edge.Addr = edgeAddr
	cfg.Edge.AllowedOrigins = []string{"https://" + edgeAddr}
	cfg.Edge.RateLimit = edge.RateLimit{PerSecond: 200, Burst: 400, Routes: map[string]edge.RateLimit{"/api/v1/tenants/resolve": {PerSecond: 5, Burst: 5}}}
	cfg.Issuer = "https://" + edgeAddr
	cfg.DB.DSN = fmt.Sprintf("postgres://auth_app:app@%s:%s/auth?sslmode=disable", pgHost, pgPorts["5432/tcp"])
	cfg.DB.MigrateDSN = adminDSN
	cfg.Valkey = config.Valkey{Addresses: []string{vkHost + ":" + vkPorts["6379/tcp"]}, Password: "test", CAFile: certPath}
	cfg.OpenFGA = config.OpenFGA{URL: fmt.Sprintf("http://%s:%s", fgaHost, fgaPorts["8080/tcp"]), PresharedKey: "test-key", AllowPlaintext: true}
	cfg.KEK = config.KEK{Source: "file", Path: kekPath}
	cfg.Email = config.Email{Transport: "smtp", Host: mpHost, Port: atoi(mpPorts["1025/tcp"]), From: "auth@example.org", AllowPlaintext: true}
	for _, m := range mutate {
		m(&cfg, pgIP)
	}

	a, err := app.Build(ctx, cfg, app.Options{Migrate: true, Freya: []freya.Option{freya.WithInsecureLocalDev()}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- a.Run(runCtx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
		}
		a.Close()
	})
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}} //nolint:gosec // dev self-signed edge cert
	env := &Env{T: t, App: a, Base: "https://" + edgeAddr, Mail: fmt.Sprintf("http://%s:%s", mpHost, mpPorts["8025/tcp"]), Client: client, Cancel: cancel, PGIP: pgIP}
	env.waitReady()
	return env
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func (e *Env) waitReady() {
	e.T.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if e.App.Freya.Ready() {
			if resp, err := e.Client.Get(e.Base + "/api/v1/session"); err == nil {
				_ = resp.Body.Close()
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	e.T.Fatal("service did not become ready")
}

// CSRF returns the double-submit token from the cookie jar.
func (e *Env) CSRF() string {
	u, _ := url.Parse(e.Base)
	for _, c := range e.Client.Jar.Cookies(u) {
		if c.Name == edge.CSRFCookie {
			return c.Value
		}
	}
	return ""
}

// sessionCookie returns the session cookie value from the jar ("" when signed out).
func (e *Env) sessionCookie() string {
	u, _ := url.Parse(e.Base)
	for _, c := range e.Client.Jar.Cookies(u) {
		if c.Name == "__Host-session" {
			return c.Value
		}
	}
	return ""
}

// JSON performs a request with the CSRF header and decodes the body.
func (e *Env) JSON(method, path string, body any, hdr ...string) (int, map[string]any) {
	e.T.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.Base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set(edge.CSRFHeader, e.CSRF())
		req.Header.Set("Origin", e.Base)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.Client.Do(req)
	if err != nil {
		e.T.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// LastMail polls Mailpit for the newest message to an address and returns its text.
func (e *Env) LastMail(to string) string {
	e.T.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(e.Mail + "/api/v1/search?query=" + url.QueryEscape("to:"+to))
		if err == nil {
			var list struct {
				Messages []struct{ ID string }
			}
			_ = json.NewDecoder(resp.Body).Decode(&list)
			_ = resp.Body.Close()
			if len(list.Messages) > 0 {
				r2, err := http.Get(e.Mail + "/api/v1/message/" + list.Messages[0].ID)
				if err == nil {
					var m struct{ Text string }
					_ = json.NewDecoder(r2.Body).Decode(&m)
					_ = r2.Body.Close()
					return m.Text
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	e.T.Fatalf("no mail for %s", to)
	return ""
}

func TestHarnessBootsAndBootstraps(t *testing.T) {
	e := Start(t)
	if code, _ := e.JSON(http.MethodGet, "/api/v1/session", nil); code != 401 {
		t.Fatalf("session without cookie → %d", code)
	}
	res, err := e.App.Bootstrap(context.Background(), "ops@example.org")
	if err != nil || res.TenantID == "" || res.KID == "" || !strings.Contains(res.AcceptURL, "token=") {
		t.Fatalf("bootstrap: %+v %v", res, err)
	}
	again, err := e.App.Bootstrap(context.Background(), "ops2@example.org")
	if err != nil || again.TenantID != res.TenantID || again.KID != res.KID || again.Created {
		t.Fatalf("bootstrap must be idempotent: %+v %v", again, err)
	}
	if mail := e.LastMail("ops@example.org"); !strings.Contains(mail, res.AcceptURL) {
		t.Fatalf("invitation mail missing link: %q", mail)
	}
}

// TestBootstrapInvitationIdempotent verifies a re-run with the SAME operator
// email reuses the outstanding invitation (no duplicate row, no second email)
// while still returning a working accept link — so the compose auth-bootstrap
// job is safe to run on every `up`.
func TestBootstrapInvitationIdempotent(t *testing.T) {
	e := Start(t)
	const em = "solo@example.org"
	r1, err := e.App.Bootstrap(context.Background(), em)
	if err != nil || r1.InvitationID == "" || r1.Reused || r1.AlreadyProvisioned {
		t.Fatalf("first bootstrap must create a fresh invitation: %+v %v", r1, err)
	}
	r2, err := e.App.Bootstrap(context.Background(), em)
	if err != nil {
		t.Fatal(err)
	}
	if r2.InvitationID != r1.InvitationID || !r2.Reused {
		t.Fatalf("second bootstrap must reuse the pending invitation: %+v", r2)
	}
	if !strings.Contains(r2.AcceptURL, "token=") {
		t.Fatalf("reused invitation must still return a working link: %+v", r2)
	}
	var n int
	if err := e.App.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM invitations WHERE tenant_id=$1 AND email=$2", r1.TenantID, em).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected exactly one invitation row for %s, got %d", em, n)
	}
}

// Seed creates an active tenant with one active user and returns their ids.
func (e *Env) Seed(slug, email, pw string, policy string) (tid, uid string) {
	e.T.Helper()
	if policy == "" {
		policy = "{}"
	}
	hash, err := password.Hash(pw)
	if err != nil {
		e.T.Fatal(err)
	}
	tid, uid = store.NewID(), store.NewID()
	err = e.App.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		// An existing slug means "another user of that tenant".
		if t, err := store.GetTenantBySlug(context.Background(), tx, slug); err == nil {
			tid = t.ID
		} else if err := store.InsertTenant(context.Background(), tx, store.Tenant{ID: tid, Slug: slug, DisplayName: strings.ToUpper(slug[:1]) + slug[1:], Status: "active", Kind: "customer", Policy: []byte(policy)}); err != nil {
			return err
		}
		return store.InsertUser(context.Background(), tx, store.User{ID: uid, TenantID: tid, Email: email, DisplayName: email, Status: "active", PasswordHash: &hash})
	})
	if err != nil {
		e.T.Fatal(err)
	}
	return tid, uid
}

// SetTenantStatus flips a tenant (e.g. to "suspended").
func (e *Env) SetTenantStatus(tid, status string) {
	e.T.Helper()
	if err := e.App.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		return store.UpdateTenantStatus(context.Background(), tx, tid, status)
	}); err != nil {
		e.T.Fatal(err)
	}
}

// SignIn signs a browser in and returns the session cookie value.
func (e *Env) SignIn(slug, email, pw string) int {
	e.T.Helper()
	code, _ := e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": slug, "email": email, "password": pw})
	return code
}

// AuditCount counts application audit rows for a tenant and event type
// (the writer batches every 500 ms).
func (e *Env) AuditCount(tid, event string) int {
	e.T.Helper()
	time.Sleep(1200 * time.Millisecond)
	var n int
	_ = e.App.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM auth_audit_events WHERE tenant_id = $1 AND event_type = $2", tid, event).Scan(&n)
	})
	return n
}

// Verifier builds an offline verifier against this instance: keys over the
// edge JWKS endpoint and the revocation feed straight from the manager.
func (e *Env) Verifier(now func() time.Time) *authclient.Verifier {
	v := authclient.New(authclient.Config{Issuer: e.App.Cfg.Issuer, UnknownKidCap: time.Millisecond},
		authclient.HTTPKeys{URL: e.Base + "/.well-known/jwks.json", Client: e.Client}, feed{e.App})
	if now != nil {
		authclient.SetClock(v, now)
	}
	if err := v.Start(context.Background(), nil); err != nil {
		e.T.Fatal(err)
	}
	return v
}

// feed adapts the in-process revocation manager to authclient.RevocationSource.
type feed struct{ a *app.App }

func (f feed) Since(ctx context.Context, cursor string) ([]authclient.Revocation, string, error) {
	since := time.Now().Add(-time.Hour)
	if cursor != "" {
		n, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil {
			return nil, cursor, err
		}
		since = time.Unix(0, n)
	}
	entries, err := f.a.Sessions.Since(ctx, since, 1000)
	if err != nil {
		return nil, cursor, err
	}
	next := strconv.FormatInt(since.UnixNano(), 10)
	out := make([]authclient.Revocation, 0, len(entries))
	for _, r := range entries {
		out = append(out, authclient.Revocation{TS: r.TS, Kind: r.Kind, SubjectID: r.SubjectID, TenantID: r.TenantID, Reason: r.Reason})
		next = strconv.FormatInt(r.TS.UnixNano(), 10)
	}
	return out, next, nil
}

func jsonDecode(r *http.Response, v any) error { return json.NewDecoder(r.Body).Decode(v) }

// SeedRoles creates the builtin roles for a tenant and returns slug → id.
func (e *Env) SeedRoles(tid string) map[string]string {
	e.T.Helper()
	ids := map[string]string{}
	err := e.App.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		for _, slug := range []string{"owner", "admin", "member", "auditor"} {
			id := store.NewID()
			if err := store.InsertRole(context.Background(), tx, store.Role{ID: id, TenantID: tid, Slug: slug, DisplayName: slug, Builtin: slug != "auditor"}); err != nil {
				return err
			}
			ids[slug] = id
		}
		return nil
	})
	if err != nil {
		e.T.Fatal(err)
	}
	return ids
}

// Bind assigns roles (mirror rows + tuples) to a user.
func (e *Env) Bind(tid, uid string, roles map[string]string, slugs ...string) {
	e.T.Helper()
	var ids []string
	var tuples []authz.Tuple
	for _, s := range slugs {
		ids = append(ids, roles[s])
		tuples = append(tuples, authz.RoleAssignmentTuple(tid, s, uid))
		if s == "owner" {
			tuples = append(tuples, authz.MembershipTuple(tid, uid, "owner"))
		}
	}
	tuples = append(tuples, authz.MembershipTuple(tid, uid, "member"))
	if err := e.App.Store.Tx(context.Background(), store.Scope{System: true}, func(tx pgx.Tx) error {
		return store.ReplaceRoleBindings(context.Background(), tx, tid, uid, uid, ids)
	}); err != nil {
		e.T.Fatal(err)
	}
	sys := tenantctx.WithActor(context.Background(), tenantctx.Actor{Kind: tenantctx.KindSystem})
	if err := e.App.Authz.Write(sys, tid, tuples, nil); err != nil {
		e.T.Fatal(err)
	}
}

// Browser returns a copy of the environment with its own cookie jar.
func (e *Env) Browser() *Env {
	jar, _ := cookiejar.New(nil)
	c := *e.Client
	c.Jar = jar
	b := *e
	b.Client = &c
	// A fresh browser receives its CSRF cookie with the first anonymous call.
	if resp, err := b.Client.Get(b.Base + "/api/v1/session"); err == nil {
		_ = resp.Body.Close()
	}
	return &b
}
