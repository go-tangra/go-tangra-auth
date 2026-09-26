package authz

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
)

func kinds(r Report) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range r.Findings {
		out[f.Kind] = append(out[f.Kind], f)
	}
	return out
}

func (f *modFixture) verifier() *Verifier { return NewVerifier(f.ms, f.c, f.aw) }

// T018: verify reports roles still waiting for a module (pending), roles a
// migration missed (loss), custom roles named like a built-in that hold
// module grants (review) and OpenFGA drift; prune-legacy refuses until it is
// clean, then removes legacy rows, mirror rows and tuples.
func TestVerifyAndPrune(t *testing.T) {
	f := newModFixture(t)
	v := f.verifier()
	ctx := f.sys
	// Before any module registered: every legacy grant is pending, no loss.
	rep, err := v.Verify(ctx, []string{tA})
	if err != nil {
		t.Fatal(err)
	}
	k := kinds(rep)
	if len(k[FindingLoss]) != 0 || len(k[FindingPending]) == 0 || rep.Clean() {
		t.Fatalf("%+v", rep)
	}
	if _, err := v.PruneLegacy(ctx, []string{tA}, false); err == nil {
		t.Fatal("prune accepted pending grants")
	}
	// Register every module holding the legacy permissions.
	for _, r := range []Registration{wardenReg(tA), ipamReg(tA)} {
		if _, err := f.mods.Register(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	rep, _ = v.Verify(ctx, []string{tA})
	if !rep.Clean() {
		t.Fatalf("after migration: %+v", rep.Findings)
	}
	// A migration gap (scoped grant removed behind auth's back) is a loss.
	backups, _ := f.ms.Role(context.Background(), tA, "r-backups")
	if _, _, err := f.roles.setGrants(ctx, tA, backups, []PermissionRef{{Resource: "backup", Action: "manage"}, {Module: "warden", Resource: "backup", Action: "manage"}}); err != nil {
		t.Fatal(err)
	}
	rep, _ = v.Verify(ctx, []string{tA})
	k = kinds(rep)
	if len(k[FindingLoss]) == 0 || rep.Losses() == 0 {
		t.Fatalf("missed migration not reported: %+v", rep.Findings)
	}
	foundRole, foundUser := false, false
	for _, l := range k[FindingLoss] {
		if l.Role == "backups" && l.Permission == "ipam:backup:manage" {
			foundRole = true
		}
		if l.User == "u-bob" && l.Permission == "ipam:backup:manage" {
			foundUser = true
		}
	}
	if !foundRole || !foundUser {
		t.Fatalf("%+v", k[FindingLoss])
	}
	if _, err := v.PruneLegacy(ctx, []string{tA}, false); err == nil {
		t.Fatal("prune accepted a loss")
	}
	// Repair, and add the D6 gap: the custom "operator" role with a module grant.
	if _, err := f.roles.addGrants(ctx, tA, backups, []PermissionRef{{Module: "ipam", Resource: "backup", Action: "manage"}}); err != nil {
		t.Fatal(err)
	}
	op, _ := f.ms.Role(context.Background(), tA, "r-op")
	if _, err := f.roles.addGrants(ctx, tA, op, []PermissionRef{{Module: "warden", Resource: "backup", Action: "manage"}}); err != nil {
		t.Fatal(err)
	}
	rep, _ = v.Verify(ctx, []string{tA})
	k = kinds(rep)
	if !rep.Clean() || len(k[FindingReview]) != 1 || k[FindingReview][0].Role != "operator" {
		t.Fatalf("%+v", rep.Findings)
	}
	// OpenFGA drift: a mirror grant without its tuple is reported.
	if err := f.fga.Fake.Write(context.Background(), nil, []Tuple{GrantTuple(tA, "readers", PermissionRef{Module: "warden", Resource: "stats", Action: "read"})}); err != nil {
		t.Fatal(err)
	}
	rep, _ = v.Verify(ctx, []string{tA})
	if k = kinds(rep); len(k[FindingDrift]) == 0 || rep.Clean() {
		t.Fatalf("drift not reported: %+v", rep.Findings)
	}
	_ = f.fga.Fake.Write(context.Background(), []Tuple{GrantTuple(tA, "readers", PermissionRef{Module: "warden", Resource: "stats", Action: "read"})}, nil)
	// Dry run counts, changes nothing.
	res, err := v.PruneLegacy(ctx, []string{tA}, true)
	if err != nil || res.Permissions != 4 || res.Grants == 0 || res.Tenants != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if perms, _ := f.ms.ListPermissions(context.Background(), tA); perms[0].Module != "" {
		t.Fatal("dry run pruned")
	}
	// Prune: legacy rows, mirror rows and tuples go; access stays.
	res, err = v.PruneLegacy(ctx, []string{tA}, false)
	if err != nil || res.Permissions != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	perms, _ := f.ms.ListPermissions(context.Background(), tA)
	for _, p := range perms {
		if p.Module == "" {
			t.Fatalf("legacy row kept: %+v", p)
		}
	}
	if got := f.grants(t, "r-backups"); !slices.Equal(got, []string{"ipam:backup:manage", "warden:backup:manage"}) {
		t.Fatalf("%v", got)
	}
	if ok, _ := f.fga.Check(context.Background(), GrantTuple(tA, "backups", PermissionRef{Resource: "backup", Action: "manage"})); ok {
		t.Fatal("legacy grant tuple kept")
	}
	if ok, _ := f.fga.Check(context.Background(), PermissionTenantTuple(tA, PermissionRef{Resource: "backup", Action: "manage"})); ok {
		t.Fatal("legacy permission tuple kept")
	}
	if !f.allowed(t, "u-bob", "warden:backup:manage") || !f.allowed(t, "u-carol", "warden:stats:read") {
		t.Fatal("access lost by prune")
	}
	if ev := f.events(audit.PermissionPruned); len(ev) != 1 || ev[0]["count"] != float64(4) {
		t.Fatalf("%v", ev)
	}
	rep, _ = v.Verify(ctx, []string{tA})
	if !rep.Clean() {
		t.Fatalf("after prune: %+v", rep.Findings)
	}
}

// SR-004: a snapshot of effective permissions before the upgrade compared
// after it shows no loss; gains are only the per-module split.
func TestSnapshotCompare(t *testing.T) {
	f := newModFixture(t)
	v := f.verifier()
	before, err := v.Snapshot(f.sys, []string{tA})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(before[tA]["u-bob"], []string{"backup:manage"}) || !slices.Equal(before[tA]["u-carol"], []string{"stats:read"}) {
		t.Fatalf("%+v", before)
	}
	js, _ := json.Marshal(before)
	var loaded Snapshot
	if err := json.Unmarshal(js, &loaded); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Registration{wardenReg(tA), ipamReg(tA)} {
		if _, err := f.mods.Register(f.sys, r); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := v.Compare(f.sys, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Losses() != 0 || len(kinds(rep)[FindingGain]) != 0 {
		t.Fatalf("%+v", rep.Findings)
	}
	// After prune the legacy refs are gone but the scoped split covers them.
	if _, err := v.PruneLegacy(f.sys, []string{tA}, false); err != nil {
		t.Fatal(err)
	}
	if rep, _ = v.Compare(f.sys, loaded); rep.Losses() != 0 {
		t.Fatalf("%+v", rep.Findings)
	}
	// Removing bob's role is a loss; a new grant outside the split is a gain.
	_ = f.ms.ReplaceBindings(context.Background(), tA, "u-bob", "", nil)
	viewer := f.roleBySlug(t, tA, "m.warden.viewer")
	f.bind(t, "u-carol", viewer.ID)
	rep, _ = v.Compare(f.sys, loaded)
	k := kinds(rep)
	if rep.Losses() == 0 || k[FindingLoss][0].User != "u-bob" || len(k[FindingGain]) == 0 {
		t.Fatalf("%+v", rep.Findings)
	}
}
