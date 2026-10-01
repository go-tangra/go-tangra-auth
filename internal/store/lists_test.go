package store

import (
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/listquery"
)

// Every list Spec is well formed and no sort field reaches a secret, a hash
// or a second-factor column (go-tangra specs/032-server-side-tables SR-006).
func TestListSpecs(t *testing.T) {
	specs := map[string]listquery.Spec{
		"users": UserList, "audit": AuditList, "members": GroupMemberList, "groups": GroupList, "roles": RoleList,
		"clients": ClientList, "tenants": TenantList, "sessions": SessionList, "directories": DirectoryList,
	}
	for name, s := range specs {
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		for field, f := range s.Fields {
			for _, bad := range []string{"password", "secret", "hash", "mfa", "token", "phone", "bind", "details", ";", "--"} {
				if strings.Contains(strings.ToLower(field+" "+f.Expr), bad) {
					t.Errorf("%s: sort field %q (%s) touches %q", name, field, f.Expr, bad)
				}
			}
		}
	}
	if got := (listquery.Request{Sort: "email", Order: listquery.Asc}).OrderBy(UserList); got != "lower(u.email) ASC NULLS LAST, u.id ASC" {
		t.Fatalf("users order %q", got)
	}
	if got := (listquery.Request{Sort: "ts", Order: listquery.Desc}).OrderBy(AuditList); got != "a.ts DESC NULLS LAST, a.id DESC" {
		t.Fatalf("audit order %q", got)
	}
}

func TestListRequestDefaults(t *testing.T) {
	r := ListRequest(listquery.Request{}, AuditList)
	if r.Page != 1 || r.PageSize != 50 || r.Sort != "ts" || r.Order != listquery.Desc {
		t.Fatalf("%+v", r)
	}
	// A hand-built invalid request falls back to the defaults.
	if r := ListRequest(listquery.Request{Sort: "nope", PageSize: 9999}, UserList); r.Sort != "email" || r.PageSize != 25 {
		t.Fatalf("%+v", r)
	}
}
