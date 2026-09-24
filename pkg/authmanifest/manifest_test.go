package authmanifest

import (
	"slices"
	"testing"

	"github.com/go-tangra/go-tangra-portal/sdk/v4/pkg/gatewayclient"
)

// TestDirectoryManifest pins the LDAP import additions (feature 016, contract B).
func TestDirectoryManifest(t *testing.T) {
	m, err := Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if Version != "1.2.0" || m.Version != "1.2.0" {
		t.Errorf("version: const %q manifest %q, want 1.2.0", Version, m.Version)
	}

	want := gatewayclient.Permission{Resource: "directory", Action: "manage", Description: "Connect LDAP directories, search them and import users as inactive"}
	n := 0
	for _, p := range m.Permissions {
		if p.Resource == "directory" {
			n++
			if p != want {
				t.Errorf("permission: got %+v want %+v", p, want)
			}
		}
	}
	if n != 1 {
		t.Errorf("want exactly one directory permission, got %d", n)
	}
	if !slices.Contains(PermissionRefs(), "directory:manage") {
		t.Error("PermissionRefs lacks directory:manage")
	}

	for slug, refs := range Grants {
		has := slices.Contains(refs, "directory:manage")
		switch slug {
		case "owner", "admin", "operator":
			if !has {
				t.Errorf("role %s must hold directory:manage", slug)
			}
		default:
			if has {
				t.Errorf("role %s must not hold directory:manage", slug)
			}
		}
	}
	for _, slug := range []string{"owner", "admin", "operator", "member", "auditor"} {
		if _, ok := Grants[slug]; !ok {
			t.Errorf("builtin role %s missing from Grants", slug)
		}
	}

	abilities := 0
	for _, a := range m.Abilities {
		if a.Requires != "directory:manage" {
			continue
		}
		abilities++
		if !slices.Equal(a.Action, []string{"manage"}) || !slices.Equal(a.Subject, []string{"DirectoryConnection"}) {
			t.Errorf("directory ability: %+v", a)
		}
	}
	if abilities != 1 {
		t.Errorf("want one directory:manage ability, got %d", abilities)
	}

	wantNav := gatewayclient.NavEntry{Title: "Directories", Path: "/console/admin/directories", Icon: "mdi-folder-account-outline", Order: 802, Requires: "directory:manage"}
	found := false
	orders := map[int32]string{}
	for _, e := range m.Nav {
		if prev, dup := orders[e.Order]; dup {
			t.Errorf("nav order %d used by %s and %s", e.Order, prev, e.Title)
		}
		orders[e.Order] = e.Title
		if e.Requires == "directory:manage" || e.Title == "Directories" {
			found = true
			if e != wantNav {
				t.Errorf("nav: got %+v want %+v", e, wantNav)
			}
		}
	}
	if !found {
		t.Error("Directories nav entry missing")
	}

	// Connection routes come from console.yaml and stay public at the gateway:
	// auth authenticates with its own session cookie and gates per tenant.
	routes := map[string]gatewayclient.Route{}
	for _, r := range m.Routes {
		routes[r.Method+" "+r.Path] = r
	}
	for _, k := range []string{
		"GET /api/v1/admin/directories", "POST /api/v1/admin/directories",
		"GET /api/v1/admin/directories/{id}", "PUT /api/v1/admin/directories/{id}",
		"POST /api/v1/admin/directories/{id}/remove", "POST /api/v1/admin/directories/test",
		"POST /api/v1/admin/directories/{id}/test",
	} {
		r, ok := routes[k]
		switch {
		case !ok:
			t.Errorf("route %s missing", k)
		case !r.Public || r.Permission != "":
			t.Errorf("route %s must be public at the gateway: %+v", k, r)
		}
	}
}
