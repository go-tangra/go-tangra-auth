package authz

import (
	"testing"

	"github.com/go-freya/freya/services/auth/internal/store"
)

func TestFoldEffectiveRoles(t *testing.T) {
	rows := []store.EffectiveRoleRow{
		{RoleID: "r1", Slug: "auditor", Source: "direct"},
		{RoleID: "r1", Slug: "auditor", Source: "group", GroupID: "g1", GroupName: "Finance"},
		{RoleID: "r1", Slug: "auditor", Source: "group", GroupID: "g2", GroupName: "Support"},
		{RoleID: "r1", Slug: "auditor", Source: "group", GroupID: "g2", GroupName: "Support"}, // duplicate row
		{RoleID: "r2", Slug: "billing", Source: "group", GroupID: "g1", GroupName: "Finance"},
	}
	out := FoldEffectiveRoles(rows)
	if len(out) != 2 {
		t.Fatalf("%+v", out)
	}
	if out[0].Slug != "auditor" || len(out[0].Sources) != 3 || out[0].Sources[0].Kind != "direct" || out[0].Sources[2].GroupName != "Support" {
		t.Fatalf("%+v", out[0])
	}
	if out[1].Slug != "billing" || len(out[1].Sources) != 1 || out[1].Sources[0].GroupID != "g1" {
		t.Fatalf("%+v", out[1])
	}
	if got := FoldEffectiveRoles(nil); got == nil || len(got) != 0 {
		t.Fatal("empty input must fold to an empty, non-nil slice")
	}
}
