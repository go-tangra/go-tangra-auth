//go:build integration

package integration

// Feature 016 end-to-end suite (quickstart Scenarios 1–3 + security checks)
// against the real T003 OpenLDAP container: TLS modes, filter/base scoping,
// alias/referral handling, limits, idempotent import, the activation →
// invitation → accept → sign-in flow, imported ≡ unknown semantics and
// cross-tenant RLS on the directory tables.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"

	"github.com/go-freya/freya/services/auth/internal/config"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/transport/edge"
)

const (
	ldapBindDN   = "cn=reader,dc=example,dc=test"
	ldapBindPW   = "reader-password"
	ldapBaseDN   = "ou=Engineering,dc=example,dc=test"
	ldapTestdata = "testdata/openldap"
)

// startLDAP builds the repo-owned T003 image, generates a throwaway test CA,
// stages the server certificate at /tls (the entrypoint blocks until it
// appears) and waits for slapd. The service dials the container's
// docker-network address — the host can route there, and the address policy
// is configured to allow exactly that host (loopback is always denied).
func startLDAP(t *testing.T) (host string, caPEM []byte) {
	t.Helper()
	ctx := context.Background()
	c, _, _ := container(t, testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{Context: ldapTestdata, Dockerfile: "Dockerfile", PrintBuildLog: true},
		ExposedPorts:   []string{"389/tcp", "636/tcp"},
		// No WaitingFor: slapd only starts after the certificates are staged
		// below, so a port wait would deadlock.
	})
	host, err := c.ContainerIP(ctx)
	if err != nil {
		t.Fatalf("openldap container address: %v", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("openldap container address %q: %v", host, err)
	}
	caPEM, certPEM, keyPEM := ldapCerts(t, ip)
	if err := c.CopyToContainer(ctx, certPEM, "/tls/server.crt", 0o444); err != nil {
		t.Fatalf("stage server.crt: %v", err)
	}
	if err := c.CopyToContainer(ctx, keyPEM, "/tls/server.key", 0o400); err != nil {
		t.Fatalf("stage server.key: %v", err)
	}
	waitForLDAP(t, host)
	return host, caPEM
}

// ldapCerts generates a per-run CA and a server certificate valid for the
// container address (plus loopback names for in-container checks).
func ldapCerts(t *testing.T, ip netip.Addr) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	serial := func() *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	notBefore := time.Now().Add(-time.Hour)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "freya ldap test ca"},
		NotBefore: notBefore, NotAfter: notBefore.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "openldap-test"},
		NotBefore: notBefore, NotAfter: notBefore.Add(48 * time.Hour), BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP(ip.String()), net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost", "openldap"}}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return caPEM, certPEM, keyPEM
}

// waitForLDAP polls the LDAPS port from the host; the docker network is
// routable, so an open port means slapd has consumed the staged certificates.
func waitForLDAP(t *testing.T, host string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "636"), 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slapd did not open ldaps on %s: %v", host, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// ldapPolicyHook denies the stack-private ranges and allows exactly the
// OpenLDAP container address, mirroring deploy/stack/configs/auth.yaml.
func ldapPolicyHook(host string) func(*config.Config, string) {
	return func(cfg *config.Config, _ string) {
		cfg.Directory.Targets.DenyCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"}
		suffix := 32
		if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
			suffix = 128
		}
		cfg.Directory.Targets.AllowCIDRs = []string{fmt.Sprintf("%s/%d", host, suffix)}
	}
}

// ldapOwner seeds a tenant with an owner bound to the owner role; the caller
// signs in with the browser it wants authenticated.
func ldapOwner(t *testing.T, e *Env, slug, email string) (tid string, roles map[string]string) {
	t.Helper()
	tid, owner := e.Seed(slug, email, pw, "")
	roles = e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	return tid, roles
}

// ldapConnInput builds a create/test body for the OpenLDAP container.
func ldapConnInput(name, rawURL, tlsMode, caPEM, bindPW, baseFilter string) map[string]any {
	in := map[string]any{
		"name": name, "kind": "openldap", "url": rawURL, "tls_mode": tlsMode,
		"bind_dn": ldapBindDN, "bind_password": bindPW, "base_dn": ldapBaseDN,
	}
	if caPEM != "" {
		in["ca_pem"] = caPEM
	}
	if baseFilter != "" {
		in["base_filter"] = baseFilter
	}
	return in
}

// createDir creates a saved ldaps connection and returns its id.
func createDir(t *testing.T, e *Env, name, ldapsURL string, caPEM []byte, baseFilter string) string {
	t.Helper()
	code, out := e.JSON(http.MethodPost, "/api/v1/admin/directories",
		ldapConnInput(name, ldapsURL, "ldaps", string(caPEM), ldapBindPW, baseFilter))
	if code != http.StatusCreated {
		t.Fatalf("create %s → %d %v", name, code, out)
	}
	return out["id"].(string)
}

// emailItems maps preview items by their (non-null) e-mail address.
func emailItems(items []any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, it := range items {
		m := it.(map[string]any)
		if em, ok := m["email"].(string); ok && em != "" {
			out[em] = m
		}
	}
	return out
}

func itemByDN(t *testing.T, items []any, dn string) map[string]any {
	t.Helper()
	for _, it := range items {
		if it.(map[string]any)["dn"] == dn {
			return it.(map[string]any)
		}
	}
	t.Fatalf("no preview item with dn %s", dn)
	return nil
}

// importSets flattens an ImportResult into uid → user_id maps (created,
// updated) and uid → reason (skipped), asserting nothing failed.
func importSets(t *testing.T, out map[string]any) (created, updated, skipped map[string]string) {
	t.Helper()
	created, updated, skipped = map[string]string{}, map[string]string{}, map[string]string{}
	for _, it := range out["created"].([]any) {
		m := it.(map[string]any)
		created[m["uid"].(string)] = m["user_id"].(string)
	}
	for _, it := range out["updated"].([]any) {
		m := it.(map[string]any)
		updated[m["uid"].(string)] = m["user_id"].(string)
	}
	for _, it := range out["skipped"].([]any) {
		m := it.(map[string]any)
		skipped[m["uid"].(string)] = m["reason"].(string)
	}
	if failed := out["failed"].([]any); len(failed) != 0 {
		t.Fatalf("unexpected import failures: %v", failed)
	}
	return created, updated, skipped
}

// rawJSON is e.JSON without decoding; used where the raw body size matters.
func rawJSON(e *Env, method, path string, body any) (int, []byte) {
	e.T.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(method, e.Base+path, bytes.NewReader(b))
	if err != nil {
		e.T.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet {
		req.Header.Set(edge.CSRFHeader, e.CSRF())
		req.Header.Set("Origin", e.Base)
	}
	resp, err := e.Client.Do(req)
	if err != nil {
		e.T.Fatalf("%s %s: %v", method, path, err)
	}
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		e.T.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, rb
}

// mailCount counts Mailpit messages to an address.
func mailCount(e *Env, to string) int {
	e.T.Helper()
	resp, err := http.Get(e.Mail + "/api/v1/search?query=" + url.QueryEscape("to:"+to))
	if err != nil {
		e.T.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var list struct {
		Messages []struct {
			ID string `json:"ID"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		e.T.Fatal(err)
	}
	return len(list.Messages)
}

// TestLDAPDirectoryConnectTLS is quickstart Scenario 1 against the real
// container: ldaps and StartTLS succeed with the pinned test CA; without the
// CA the tls step fails closed; a wrong bind password fails the bind step.
func TestLDAPDirectoryConnectTLS(t *testing.T) {
	host, caPEM := startLDAP(t)
	e := Start(t, ldapPolicyHook(host))
	ldapOwner(t, e, "acme", "owner@acme.test")
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	ldapsURL := "ldaps://" + net.JoinHostPort(host, "636")

	connID := createDir(t, e, "corp-dir", ldapsURL, caPEM, "")
	code, out := e.JSON(http.MethodGet, "/api/v1/admin/directories/"+connID, nil)
	if code != http.StatusOK {
		t.Fatalf("get connection → %d", code)
	}
	if out["bind_password_set"] != true || out["ca_pem_set"] != true {
		t.Fatalf("flags: %v", out)
	}
	if _, leaked := out["bind_password"]; leaked {
		t.Fatal("connection view leaks the bind password")
	}

	// ldaps: saved-connection test persists last_test.
	code, out = e.JSON(http.MethodPost, "/api/v1/admin/directories/"+connID+"/test", nil)
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("ldaps test → %d %v", code, out)
	}
	if info := out["tls"].(map[string]any); info["version"] != "TLS 1.3" {
		t.Fatalf("tls info: %v", info)
	}
	if out["step"] != nil || out["reason"] != nil {
		t.Fatalf("successful test carries failure fields: %v", out)
	}
	code, out = e.JSON(http.MethodGet, "/api/v1/admin/directories/"+connID, nil)
	if code != http.StatusOK {
		t.Fatalf("get connection after test → %d %v", code, out)
	}
	if lt := out["last_test"].(map[string]any); lt["outcome"] != "ok" {
		t.Fatalf("last_test not persisted: %v", out["last_test"])
	}

	// StartTLS on 389 with the pinned CA.
	code, out = e.JSON(http.MethodPost, "/api/v1/admin/directories/test",
		ldapConnInput("probe-starttls", "ldap://"+net.JoinHostPort(host, "389"), "starttls", string(caPEM), ldapBindPW, ""))
	if code != http.StatusOK || out["ok"] != true || out["tls"].(map[string]any)["version"] != "TLS 1.3" {
		t.Fatalf("starttls test → %d %v", code, out)
	}

	// Untrusted CA: the harness CA is per-run, so system roots cannot verify
	// the server certificate.
	code, out = e.JSON(http.MethodPost, "/api/v1/admin/directories/test",
		ldapConnInput("probe-badca", ldapsURL, "ldaps", "", ldapBindPW, ""))
	if code != http.StatusOK || out["ok"] != false || out["step"] != "tls" || out["reason"] != "tls_failed" {
		t.Fatalf("untrusted CA → %d %v", code, out)
	}

	// Wrong bind password.
	code, out = e.JSON(http.MethodPost, "/api/v1/admin/directories/test",
		ldapConnInput("probe-badpw", ldapsURL, "ldaps", string(caPEM), "wrong-password", ""))
	if code != http.StatusOK || out["ok"] != false || out["step"] != "bind" || out["reason"] != "invalid_credentials" {
		t.Fatalf("wrong password → %d %v", code, out)
	}
}

// TestLDAPDirectorySearchImportActivate is quickstart Scenarios 2 and 3: base
// and user filters combine, the ou=Secret alias target never appears,
// referrals to an unresolvable host are not followed, the size limit
// truncates, the 1 MiB attribute stays on the directory side, import is
// idempotent, and an activated user gets the standard invitation flow.
func TestLDAPDirectorySearchImportActivate(t *testing.T) {
	host, caPEM := startLDAP(t)
	e := Start(t, ldapPolicyHook(host))
	_, roles := ldapOwner(t, e, "acme", "owner@acme.test")
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		t.Fatal("sign-in")
	}
	ldapsURL := "ldaps://" + net.JoinHostPort(host, "636")
	filteredID := createDir(t, e, "eng-filtered", ldapsURL, caPEM, "(departmentNumber=42)")
	plainID := createDir(t, e, "eng-plain", ldapsURL, caPEM, "")

	// Base filter: the connection filter (departmentNumber=42) is combined
	// with the match-all user filter; the departmentNumber=7 outlier, the
	// alias and the referral object do not match it.
	_, out := e.JSON(http.MethodPost, "/api/v1/admin/directories/"+filteredID+"/search", map[string]any{})
	if out["effective_filter"] != "(&(departmentNumber=42)(objectClass=*))" {
		t.Fatalf("effective filter: %v", out["effective_filter"])
	}
	items := out["items"].([]any)
	if len(items) != 6 {
		t.Fatalf("base-filtered search returned %d items: %v", len(items), out)
	}
	for _, it := range items {
		if !strings.HasSuffix(it.(map[string]any)["dn"].(string), ldapBaseDN) {
			t.Errorf("entry outside the base: %v", it)
		}
	}
	byEmail := emailItems(items)
	if _, ok := byEmail["outlier@example.test"]; ok {
		t.Error("base filter (departmentNumber=42) leaked the departmentNumber=7 outlier")
	}

	// Base filter + user filter: exact combined canonical filter, one match.
	_, out = e.JSON(http.MethodPost, "/api/v1/admin/directories/"+filteredID+"/search", map[string]any{"filter": "(uid=eng1)"})
	if out["effective_filter"] != "(&(departmentNumber=42)(uid=eng1))" {
		t.Fatalf("effective filter: %v", out["effective_filter"])
	}
	if items := out["items"].([]any); len(items) != 1 || items[0].(map[string]any)["email"] != "eng1@example.test" {
		t.Fatalf("user-filtered search: %v", out)
	}

	// Alias + referral on the unfiltered connection. The alias points at
	// cn=hidden,ou=Secret (outside the base) and the referral object points
	// at an unresolvable host: success with entries proves the alias target
	// was not dereferenced into the result and no referral was followed.
	_, out = e.JSON(http.MethodPost, "/api/v1/admin/directories/"+plainID+"/search", map[string]any{})
	items = out["items"].([]any)
	byEmail = emailItems(items)
	if _, ok := byEmail["hidden@example.test"]; ok {
		t.Fatal("alias target in ou=Secret was returned")
	}
	for _, it := range items {
		if strings.Contains(it.(map[string]any)["dn"].(string), "ou=Secret") {
			t.Fatalf("entry outside the base returned: %v", it)
		}
	}
	if _, ok := byEmail["outlier@example.test"]; !ok {
		t.Fatal("unfiltered search must include the outlier")
	}
	if eng4 := itemByDN(t, items, "uid=eng4,"+ldapBaseDN); eng4["status"] != "invalid" || eng4["reason"] != "no_email" {
		t.Fatalf("no-mail entry preview: %v", eng4)
	}

	// Size limit: two entries plus the truncation flag.
	if code, out := e.JSON(http.MethodPut, "/api/v1/admin/directories/"+filteredID, map[string]any{"size_limit": 2}); code != http.StatusOK {
		t.Fatalf("set size_limit → %d %v", code, out)
	}
	_, out = e.JSON(http.MethodPost, "/api/v1/admin/directories/"+filteredID+"/search", map[string]any{})
	if out["truncated"] != true || len(out["items"].([]any)) != 2 {
		t.Fatalf("size-limit truncation: %v", out)
	}
	if code, _ := e.JSON(http.MethodPut, "/api/v1/admin/directories/"+filteredID, map[string]any{"size_limit": 100}); code != http.StatusOK {
		t.Fatal("restore size_limit")
	}

	// The 1 MiB description on uid=eng5 is never requested nor transferred:
	// the preview decodes the mapped attributes only, so a response carrying
	// the entry stays small.
	code, raw := rawJSON(e, http.MethodPost, "/api/v1/admin/directories/"+plainID+"/search", map[string]any{"filter": "(uid=eng5)"})
	if code != http.StatusOK {
		t.Fatalf("eng5 search → %d", code)
	}
	if len(raw) > 64*1024 {
		t.Fatalf("1 MiB attribute crossed the API boundary: %d bytes", len(raw))
	}
	var eng5out map[string]any
	if err := json.Unmarshal(raw, &eng5out); err != nil {
		t.Fatal(err)
	}
	eng5 := eng5out["items"].([]any)[0].(map[string]any)
	if eng5["email"] != "eng5@example.test" || eng5["display_name"] != "Eng Five" {
		t.Fatalf("eng5 preview: %v", eng5)
	}

	// Import: created for the four unique-mail people, skipped for the
	// no-mail entry and the duplicate-mail twin; re-import updates instead
	// of duplicating (SC-004).
	uidOf := func(email string) string {
		m, ok := byEmail[email]
		if !ok || m["uid"] == nil {
			t.Fatalf("plain preview missing %s: %v", email, items)
		}
		return m["uid"].(string)
	}
	uids := map[string]string{
		"eng1": uidOf("eng1@example.test"),
		"eng2": uidOf("eng2@example.test"),
		"eng4": itemByDN(t, items, "uid=eng4,"+ldapBaseDN)["uid"].(string), // no mail
		"eng5": uidOf("eng5@example.test"),
		"eng6": itemByDN(t, items, "uid=eng6,"+ldapBaseDN)["uid"].(string), // shares eng-twins@
		"eng7": itemByDN(t, items, "uid=eng7,"+ldapBaseDN)["uid"].(string), // shares eng-twins@
	}
	importBody := map[string]any{"uids": []string{uids["eng1"], uids["eng2"], uids["eng4"], uids["eng5"], uids["eng6"], uids["eng7"]}}
	_, out = e.JSON(http.MethodPost, "/api/v1/admin/directories/"+plainID+"/import", importBody)
	created, updated, skipped := importSets(t, out)
	if len(created) != 4 || created[uids["eng1"]] == "" || created[uids["eng2"]] == "" ||
		created[uids["eng5"]] == "" || created[uids["eng6"]] == "" {
		t.Fatalf("import created: %v", out)
	}
	if len(updated) != 0 || !reflect.DeepEqual(skipped, map[string]string{uids["eng4"]: "no_email", uids["eng7"]: "duplicate_email"}) {
		t.Fatalf("import skipped/updated: %v", out)
	}

	_, out = e.JSON(http.MethodPost, "/api/v1/admin/directories/"+plainID+"/import", importBody)
	created, updated, skipped = importSets(t, out)
	if len(created) != 0 || len(updated) != 4 || !reflect.DeepEqual(skipped, map[string]string{uids["eng4"]: "no_email", uids["eng7"]: "duplicate_email"}) {
		t.Fatalf("re-import must update in place: %v", out)
	}

	// Imported users are listed with their origin; no duplicate rows exist.
	_, out = e.JSON(http.MethodGet, "/api/v1/admin/users?status=imported", nil)
	items = out["items"].([]any)
	if len(items) != 4 {
		t.Fatalf("imported users: %v", out)
	}
	usersByEmail := map[string]map[string]any{}
	for _, it := range items {
		m := it.(map[string]any)
		if m["status"] != "imported" {
			t.Fatalf("status filter leak: %v", m)
		}
		dir := m["directory"].(map[string]any)
		if dir["connection_name"] != "eng-plain" || dir["directory_uid"] == "" {
			t.Fatalf("origin: %v", m)
		}
		usersByEmail[m["email"].(string)] = m
	}
	if _, out := e.JSON(http.MethodGet, "/api/v1/admin/users", nil); len(out["items"].([]any)) != 5 {
		t.Fatalf("user rows were duplicated: %v", out)
	}

	// Activation: the standard invitation, accepted, ends in a sign-in.
	eng1ID := usersByEmail["eng1@example.test"]["id"].(string)
	code, out = e.JSON(http.MethodPost, "/api/v1/admin/users/activate",
		map[string]any{"user_ids": []string{eng1ID}, "role_ids": []string{roles["member"]}})
	if code != http.StatusOK {
		t.Fatalf("activate → %d %v", code, out)
	}
	item := out["items"].([]any)[0].(map[string]any)
	if item["user_id"] != eng1ID || item["outcome"] != "invited" || item["invitation_id"] == nil || item["reason"] != nil {
		t.Fatalf("activate item: %v", item)
	}
	mail := e.LastMail("eng1@example.test")
	tok := regexp.MustCompile(`token=([A-Za-z0-9_-]+)`).FindStringSubmatch(mail)
	if tok == nil {
		t.Fatalf("no accept token in invitation: %q", mail)
	}
	eng1 := e.Browser()
	if code, _ := eng1.JSON(http.MethodPost, "/api/v1/invitations/accept",
		map[string]string{"token": tok[1], "display_name": "", "password": "a-long-enough-password"}); code != http.StatusOK {
		t.Fatalf("accept → %d", code)
	}
	_, sess := eng1.JSON(http.MethodGet, "/api/v1/session", nil)
	if sess["user"].(map[string]any)["display_name"] != "Eng One" {
		t.Fatalf("profile from imported names: %v", sess)
	}
	if code := e.Browser().SignIn("acme", "eng1@example.test", "a-long-enough-password"); code != http.StatusOK {
		t.Fatalf("activated user sign-in → %d", code)
	}

	// Origin survives activation; the user left the imported list.
	_, out = e.JSON(http.MethodGet, "/api/v1/admin/users?status=imported", nil)
	if items := out["items"].([]any); len(items) != 3 {
		t.Fatalf("imported list after activation: %v", out)
	}
	_, out = e.JSON(http.MethodGet, "/api/v1/admin/users", nil)
	active := emailItems(out["items"].([]any))["eng1@example.test"]
	if active["status"] != "active" || active["directory"].(map[string]any)["connection_name"] != "eng-plain" {
		t.Fatalf("activated user: %v", active)
	}

	// Imported ≡ unknown for sign-in and recovery: identical refusal, no
	// lockout after repeated attempts, no e-mail is ever sent.
	anon := e.Browser()
	signin := func(email, password string) (int, map[string]any) {
		return anon.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": email, "password": password})
	}
	ci, oi := signin("eng2@example.test", pw)
	cu, ou := signin("nobody@example.test", pw)
	if ci != http.StatusUnauthorized || cu != http.StatusUnauthorized || oi["reason"] != "invalid_credentials" || !reflect.DeepEqual(oi, ou) {
		t.Fatalf("imported %d %v vs unknown %d %v", ci, oi, cu, ou)
	}
	for i := 0; i < 10; i++ {
		if code, out := signin("eng2@example.test", "wrong"); code != http.StatusUnauthorized || out["reason"] != "invalid_credentials" {
			t.Fatalf("attempt %d → %d %v", i, code, out)
		}
	}
	if code, _ := signin("eng2@example.test", pw); code != http.StatusUnauthorized {
		t.Fatalf("imported account must never lock out, got %d", code)
	}
	_, ri := anon.JSON(http.MethodPost, "/api/v1/recovery", map[string]string{"tenant": "acme", "email": "eng2@example.test"})
	_, ru := anon.JSON(http.MethodPost, "/api/v1/recovery", map[string]string{"tenant": "acme", "email": "nobody@example.test"})
	if !reflect.DeepEqual(ri, ru) || ri["queued"] != true {
		t.Fatalf("recovery imported %v vs unknown %v", ri, ru)
	}
	if n := mailCount(e, "eng2@example.test"); n != 0 {
		t.Fatalf("imported user received %d messages", n)
	}
	if n := mailCount(e, "eng5@example.test"); n != 0 {
		t.Fatalf("imported user received %d messages", n)
	}
	if n := mailCount(e, "eng1@example.test"); n == 0 {
		t.Fatal("activation invitation never arrived (mail check is vacuous)")
	}
}

// TestLDAPDirectoryCrossTenantRLS: quickstart cross-tenant check — tenant B
// has no API or SQL visibility into tenant A's connection, links or imports.
func TestLDAPDirectoryCrossTenantRLS(t *testing.T) {
	host, caPEM := startLDAP(t)
	e := Start(t, ldapPolicyHook(host))
	tA, _ := ldapOwner(t, e, "acme", "owner@acme.test")
	tB, _ := ldapOwner(t, e, "globex", "owner@globex.test")
	a, b := e.Browser(), e.Browser()
	a.SignIn("acme", "owner@acme.test", pw)
	b.SignIn("globex", "owner@globex.test", pw)

	// A connects and imports one user, so both new tables hold A rows.
	connID := createDir(t, a, "acme-dir", "ldaps://"+net.JoinHostPort(host, "636"), caPEM, "")
	_, out := a.JSON(http.MethodPost, "/api/v1/admin/directories/"+connID+"/search", map[string]any{})
	uid := emailItems(out["items"].([]any))["eng1@example.test"]["uid"].(string)
	_, out = a.JSON(http.MethodPost, "/api/v1/admin/directories/"+connID+"/import", map[string]any{"uids": []string{uid}})
	created, _, _ := importSets(t, out)
	if len(created) != 1 {
		t.Fatalf("import: %v", out)
	}

	// B's API surface: empty list, every guess 404s.
	if code, out := b.JSON(http.MethodGet, "/api/v1/admin/directories", nil); code != http.StatusOK || len(out["items"].([]any)) != 0 {
		t.Fatalf("B lists A's connections: %d %v", code, out)
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/v1/admin/directories/" + connID, nil},
		{http.MethodPut, "/api/v1/admin/directories/" + connID, map[string]any{"name": "hijack"}},
		{http.MethodPost, "/api/v1/admin/directories/" + connID + "/test", nil},
		{http.MethodPost, "/api/v1/admin/directories/" + connID + "/search", map[string]any{}},
		{http.MethodPost, "/api/v1/admin/directories/" + connID + "/import", map[string]any{"uids": []string{uid}}},
		{http.MethodPost, "/api/v1/admin/directories/" + connID + "/remove", nil},
	} {
		if code, _ := b.JSON(c.method, c.path, c.body); code != http.StatusNotFound {
			t.Errorf("B %s %s → %d, want 404", c.method, c.path, code)
		}
	}

	// B at the SQL layer (RLS): no A rows in either new table, while A's own
	// context sees exactly one row in each (the counts are real).
	count := func(tid, table string) int {
		t.Helper()
		var n int
		err := e.App.Store.Tx(context.Background(), store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), "SELECT count(*) FROM "+table+" WHERE tenant_id = $1", tA).Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, table := range []string{"directory_connections", "user_directory_links"} {
		if n := count(tB, table); n != 0 {
			t.Fatalf("RLS leak: B sees %d of A's rows in %s", n, table)
		}
		if n := count(tA, table); n != 1 {
			t.Fatalf("A must see its own %s row, got %d", table, n)
		}
	}
}
