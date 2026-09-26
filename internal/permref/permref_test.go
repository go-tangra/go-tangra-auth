package permref

import (
	"errors"
	"strings"
	"testing"
)

const tid = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

func TestParseQualified(t *testing.T) {
	r, err := Parse("warden:backup:manage")
	if err != nil || r != (Ref{Module: "warden", Resource: "backup", Action: "manage"}) {
		t.Fatalf("%+v %v", r, err)
	}
	if r.String() != "warden:backup:manage" || r.Short() != "backup:manage" || r.IsLegacy() {
		t.Fatalf("%q %q %v", r.String(), r.Short(), r.IsLegacy())
	}
	for _, s := range []string{
		"", ":", "::", "warden::manage", ":backup:manage", "warden:backup:", "warden:backup:manage:x",
		"backup:manage", "Warden:backup:manage", "warden:Backup:manage", "warden:backup:Manage",
		"warden~x:backup:manage", "warden:back/up:manage", "warden:backup:man~age", "1warden:backup:manage",
		"warden:1backup:manage", "warden:backup:1manage", "war_den:backup:manage", "warden:back.up:manage",
		strings.Repeat("a", 33) + ":backup:manage", "warden:" + strings.Repeat("a", 65) + ":manage",
		"warden:backup:" + strings.Repeat("a", 33), "warden :backup:manage", "warden:backup:manage\n",
	} {
		if _, err := Parse(s); !errors.Is(err, ErrMalformed) {
			t.Errorf("accepted %q", s)
		}
	}
	// Boundary lengths are accepted.
	long := strings.Repeat("a", 32) + ":" + strings.Repeat("b", 64) + ":" + strings.Repeat("c", 32)
	if r, err := Parse(long); err != nil || r.String() != long {
		t.Fatalf("boundary: %v", err)
	}
	if r, err := Parse("ip-am:ip_groups:read-all"); err != nil || r.Module != "ip-am" {
		t.Fatalf("dash/underscore: %v", err)
	}
}

func TestParseLegacyAndAny(t *testing.T) {
	r, err := ParseLegacy("backup:manage")
	if err != nil || r != (Ref{Resource: "backup", Action: "manage"}) || !r.IsLegacy() || r.String() != "backup:manage" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, s := range []string{"warden:backup:manage", "backup", ":manage", "backup:", "B:m", "b:m~"} {
		if _, err := ParseLegacy(s); err == nil {
			t.Errorf("legacy accepted %q", s)
		}
	}
	if r, err := ParseAny("warden:backup:manage"); err != nil || r.Module != "warden" {
		t.Fatalf("any qualified: %+v %v", r, err)
	}
	if r, err := ParseAny("backup:manage"); err != nil || !r.IsLegacy() {
		t.Fatalf("any legacy: %+v %v", r, err)
	}
	for _, s := range []string{"", "a", "a:b:c:d", "A:b"} {
		if _, err := ParseAny(s); err == nil {
			t.Errorf("any accepted %q", s)
		}
	}
}

func TestQualifyAndWithModule(t *testing.T) {
	r, err := Qualify("ipam", "backup:manage")
	if err != nil || r.String() != "ipam:backup:manage" {
		t.Fatalf("%v %v", r, err)
	}
	for _, c := range [][2]string{{"", "backup:manage"}, {"IPAM", "backup:manage"}, {"ipam", "warden:backup:manage"}, {"ipam", "bad"}} {
		if _, err := Qualify(c[0], c[1]); err == nil {
			t.Errorf("qualify accepted %q %q", c[0], c[1])
		}
	}
	legacy := Ref{Resource: "backup", Action: "manage"}
	if got := legacy.WithModule("warden"); got.String() != "warden:backup:manage" || !legacy.IsLegacy() {
		t.Fatalf("%v", got)
	}
}

func TestValidators(t *testing.T) {
	cases := []struct {
		f    func(string) bool
		ok   []string
		bad  []string
		name string
	}{
		{ValidModule, []string{"a", "warden", "ipam-2", strings.Repeat("a", 32)}, []string{"", "1a", "-a", "A", "a_b", "a.b", strings.Repeat("a", 33)}, "module"},
		{ValidResource, []string{"a", "ip_groups", "a-b", strings.Repeat("a", 64)}, []string{"", "1a", "_a", "a.b", strings.Repeat("a", 65)}, "resource"},
		{ValidAction, []string{"read", "read_all", strings.Repeat("a", 32)}, []string{"", "Read", "a~", strings.Repeat("a", 33)}, "action"},
		{ValidRoleDefSlug, []string{"viewer", "a", "0", "read-only", strings.Repeat("a", 32)}, []string{"", "-a", "a-", "A", "a.b", "a_b", strings.Repeat("a", 33)}, "role def slug"},
	}
	for _, c := range cases {
		for _, s := range c.ok {
			if !c.f(s) {
				t.Errorf("%s refused %q", c.name, s)
			}
		}
		for _, s := range c.bad {
			if c.f(s) {
				t.Errorf("%s accepted %q", c.name, s)
			}
		}
	}
}

func TestObjects(t *testing.T) {
	scoped := Ref{Module: "warden", Resource: "backup", Action: "manage"}
	legacy := Ref{Resource: "backup", Action: "manage"}
	if got := scoped.Object(tid); got != "permission:"+tid+"/warden~backup~manage" {
		t.Fatal(got)
	}
	if got := legacy.Object(tid); got != "permission:"+tid+"/backup~manage" {
		t.Fatal(got)
	}
	for _, r := range []Ref{scoped, legacy} {
		gotTid, got, err := ParseObject(r.Object(tid))
		if err != nil || gotTid != tid || got != r {
			t.Fatalf("round trip %v: %v %v %v", r, gotTid, got, err)
		}
	}
	for _, s := range []string{
		"", "permission:", "role:" + tid + "/x", "permission:" + tid, "permission:" + tid + "/",
		"permission:not-a-uuid/a~b", "permission:" + tid + "/a~b~c~d", "permission:" + tid + "/A~b",
		"permission:" + tid + "/a:b", "permission:" + tid + "/w~a~", "permission:" + tid + "/a/b~c",
		"permission:" + strings.ToUpper(tid) + "/a~b", "permission:" + tid + "/~a~b",
	} {
		if _, _, err := ParseObject(s); !errors.Is(err, ErrMalformed) {
			t.Errorf("object accepted %q", s)
		}
	}
}

func TestModuleFromSPIFFE(t *testing.T) {
	for id, want := range map[string]string{
		"spiffe://example.org/svc/warden":  "warden",
		"spiffe://freya.local/svc/ipam-2":  "ipam-2",
		"spiffe://td/svc/" + "a":           "a",
		"spiffe://example.org/svc/gateway": "gateway",
	} {
		if got, err := ModuleFromSPIFFE(id); err != nil || got != want {
			t.Errorf("%q → %q %v", id, got, err)
		}
	}
	for _, id := range []string{
		"", "warden", "spiffe://", "spiffe:///svc/warden", "spiffe://example.org", "spiffe://example.org/",
		"spiffe://example.org/svc/", "spiffe://example.org/svc/warden/x", "spiffe://example.org/user/warden",
		"spiffe://example.org/svc/Warden", "spiffe://example.org/svc/1warden", "https://example.org/svc/warden",
		"spiffe://example.org/ns/x/svc/warden", "spiffe://example.org/svc/" + strings.Repeat("a", 33),
		"spiffe://example.org/svc/war_den",
	} {
		if _, err := ModuleFromSPIFFE(id); !errors.Is(err, ErrMalformed) {
			t.Errorf("accepted %q", id)
		}
	}
}

func TestModuleRoleSlug(t *testing.T) {
	s, err := ModuleRoleSlug("warden", "viewer")
	if err != nil || s != "m.warden.viewer" {
		t.Fatalf("%q %v", s, err)
	}
	m, slug, ok := ParseModuleRoleSlug(s)
	if !ok || m != "warden" || slug != "viewer" {
		t.Fatalf("%q %q %v", m, slug, ok)
	}
	for _, c := range [][2]string{{"", "viewer"}, {"Warden", "viewer"}, {"warden", ""}, {"warden", "a.b"}, {"warden", "-x"}} {
		if _, err := ModuleRoleSlug(c[0], c[1]); !errors.Is(err, ErrMalformed) {
			t.Errorf("built %q %q", c[0], c[1])
		}
	}
	for _, s := range []string{"", "viewer", "m.", "m.warden", "m.warden.", "m..viewer", "x.warden.viewer", "m.warden.viewer.x", "m.Warden.viewer", "m.warden.-v"} {
		if _, _, ok := ParseModuleRoleSlug(s); ok {
			t.Errorf("parsed %q", s)
		}
	}
}

func TestCustomSlugs(t *testing.T) {
	for _, s := range []string{"billing", "a", "sales-eu", strings.Repeat("a", 63)} {
		if got, err := ParseCustomSlug(s); err != nil || got != s {
			t.Errorf("refused %q: %v", s, err)
		}
	}
	for _, s := range []string{"", "-a", "a-", "A", "a.b", "m.warden.viewer", "a_b", strings.Repeat("a", 64), "owner", "admin", "member", "auditor", "operator"} {
		if _, err := ParseCustomSlug(s); !errors.Is(err, ErrMalformed) {
			t.Errorf("accepted %q", s)
		}
	}
	for _, s := range ReservedSlugs {
		if !IsReserved(s) {
			t.Errorf("%q not reserved", s)
		}
	}
	if IsReserved("billing") || len(ReservedSlugs) != 5 {
		t.Fatal("reserved set")
	}
}
