//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
)

// TestRolesPlaywright (feature 019, T068) runs console/tests/e2e/roles.spec.ts
// against this service with warden and ipam registered: the role editor
// grouped by module and the clone of a module role. Like the feature 018
// scenario it needs Node, the console dependencies and a Chromium
// (PW_CHANNEL=chrome for the system Chrome), so it only runs when
// E2E_PLAYWRIGHT=1.
func TestRolesPlaywright(t *testing.T) {
	if os.Getenv("E2E_PLAYWRIGHT") != "1" {
		t.Skip("set E2E_PLAYWRIGHT=1 to run the console module-roles scenario")
	}
	e := Start(t)
	const tenant, em, pwd = "roles", "owner@roles.test", "roles-password-1"
	tid, owner := e.Seed(tenant, em, pwd, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	for _, reg := range []authz.Registration{
		{Module: "warden", DisplayName: "Warden", Registrant: "spiffe://example.org/svc/warden", Tenants: []string{tid}, DeclaresRoles: true,
			Permissions: []authz.Permission{{Resource: "secrets", Action: "read", Description: "Read secrets"}, {Resource: "backup", Action: "manage", Description: "Export and import backups"}},
			Roles:       []authz.ModuleRole{{Slug: "viewer", DisplayName: "Warden viewer", Description: "Read secrets", Permissions: []string{"secrets:read"}}}},
		{Module: "ipam", DisplayName: "IPAM", Registrant: "spiffe://example.org/svc/ipam", Tenants: []string{tid},
			Permissions: []authz.Permission{{Resource: "backup", Action: "manage", Description: "Export and import backups"}}},
	} {
		if _, err := e.App.Modules.Register(sysCtx(), reg); err != nil {
			t.Fatal(err)
		}
	}
	port := freeLocalPort(t)
	origin := "http://localhost:" + port
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
	pwt := exec.CommandContext(ctx, "npx", "playwright", "test", "tests/e2e/roles.spec.ts", "--reporter=list")
	pwt.Dir = consoleDir
	pwt.Env = append(os.Environ(), "AUTH_BASE_URL="+origin, "E2E_ROLES_TENANT="+tenant, "E2E_ROLES_EMAIL="+em, "E2E_ROLES_PASSWORD="+pwd)
	pwt.Stdout, pwt.Stderr = os.Stderr, os.Stderr
	if err := pwt.Run(); err != nil {
		t.Fatalf("playwright: %v", err)
	}
	for _, ev := range []string{"role_created", "role_cloned"} {
		if n := e.AuditCount(tid, ev); n != 1 {
			t.Errorf("audit %s = %d, want 1", ev, n)
		}
	}
}
