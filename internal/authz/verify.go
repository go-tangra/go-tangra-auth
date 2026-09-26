package authz

import (
	"context"
	"errors"
	"sort"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Finding kinds of a verification (feature 019, SR-004).
const (
	// FindingLoss: a legacy grant whose module-scoped counterpart is missing
	// although the module registered the permission (role or user level).
	FindingLoss = "loss"
	// FindingPending: a legacy grant no module has registered scoped yet;
	// pruning now would remove it.
	FindingPending = "pending"
	// FindingDrift: a mirror grant OpenFGA does not confirm.
	FindingDrift = "drift"
	// FindingReview: a custom role named like a built-in that received
	// module grants before 019 (research D6); kept for an administrator.
	FindingReview = "review"
	// FindingGain: an effective permission beyond the per-module split
	// (snapshot comparison only; informational).
	FindingGain = "gain"
)

// Finding is one verification result.
type Finding struct {
	Tenant     string `json:"tenant"`
	Kind       string `json:"kind"`
	Role       string `json:"role,omitempty"`
	User       string `json:"user,omitempty"`
	Permission string `json:"permission"`
}

// Report is the outcome of Verify or Compare.
type Report struct {
	Tenants  int       `json:"tenants"`
	Findings []Finding `json:"findings"`
}

func (r Report) count(kind string) int {
	n := 0
	for _, f := range r.Findings {
		if f.Kind == kind {
			n++
		}
	}
	return n
}

// Losses counts loss findings.
func (r Report) Losses() int { return r.count(FindingLoss) }

// Clean reports whether pruning the legacy permissions loses nothing: no
// loss, no pending grant, no drift.
func (r Report) Clean() bool {
	return r.count(FindingLoss) == 0 && r.count(FindingPending) == 0 && r.count(FindingDrift) == 0
}

// Snapshot is every active user's effective permissions per tenant.
type Snapshot map[string]map[string][]string

// VerifyStore is what verification and pruning read and delete.
type VerifyStore interface {
	ListPermissions(ctx context.Context, tenantID string) ([]store.Permission, error)
	ListRoles(ctx context.Context, tenantID string) ([]store.Role, error)
	RolePermissions(ctx context.Context, tenantID, roleID string) ([]PermissionRef, error)
	EffectiveRoles(ctx context.Context, tenantID, userID string) ([]store.EffectiveRoleRow, error)
	ListActiveMemberIDs(ctx context.Context, tenantID, after string, limit int, ids []string) ([]string, error)
	DeleteLegacyPermissions(ctx context.Context, tenantID string) (int64, error)
}

// Verifier compares legacy and module-scoped grants (authsvc permissions
// verify) and removes the legacy ones once nothing depends on them
// (authsvc permissions prune-legacy).
type Verifier struct {
	st    VerifyStore
	authz *Client
	audit *audit.Writer
	// SampleUsers bounds the users per tenant whose grants are confirmed
	// against OpenFGA (0 = 50).
	SampleUsers int
}

// NewVerifier wires the verifier.
func NewVerifier(st VerifyStore, c *Client, a *audit.Writer) *Verifier {
	return &Verifier{st: st, authz: c, audit: a}
}

// tenantState is what one tenant's verification needs.
type tenantState struct {
	scopedBy map[string][]string // "res:act" → modules registering it scoped
	legacy   map[PermissionRef]bool
	roles    []store.Role
	grants   map[string]map[PermissionRef]bool // role id → grants
	users    map[string]map[PermissionRef]bool // user id → effective grants
}

func (v *Verifier) load(ctx context.Context, tid string) (*tenantState, error) {
	s := &tenantState{scopedBy: map[string][]string{}, legacy: map[PermissionRef]bool{}, grants: map[string]map[PermissionRef]bool{}, users: map[string]map[PermissionRef]bool{}}
	perms, err := v.st.ListPermissions(ctx, tid)
	if err != nil {
		return nil, err
	}
	for _, p := range perms {
		if p.Module == "" {
			s.legacy[p.Ref()] = true
		} else {
			s.scopedBy[p.Ref().Short()] = append(s.scopedBy[p.Ref().Short()], p.Module)
		}
	}
	for k := range s.scopedBy {
		sort.Strings(s.scopedBy[k])
	}
	if s.roles, err = v.st.ListRoles(ctx, tid); err != nil {
		return nil, err
	}
	for _, r := range s.roles {
		ps, err := v.st.RolePermissions(ctx, tid, r.ID)
		if err != nil {
			return nil, err
		}
		set := map[PermissionRef]bool{}
		for _, p := range ps {
			set[p] = true
		}
		s.grants[r.ID] = set
	}
	after := ""
	for {
		ids, err := v.st.ListActiveMemberIDs(ctx, tid, after, 1000, nil)
		if err != nil {
			return nil, err
		}
		for _, uid := range ids {
			rows, err := v.st.EffectiveRoles(ctx, tid, uid)
			if err != nil {
				return nil, err
			}
			eff := map[PermissionRef]bool{}
			for _, row := range rows {
				for p := range s.grants[row.RoleID] {
					eff[p] = true
				}
			}
			s.users[uid] = eff
		}
		if len(ids) < 1000 {
			break
		}
		after = ids[len(ids)-1]
	}
	return s, nil
}

func sortedRefs(set map[PermissionRef]bool) []PermissionRef {
	out := make([]PermissionRef, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Verify checks each tenant: per role and per user (directly and through
// groups) every legacy grant must have its module-scoped counterpart for
// every module registering it; grants no module registered are pending; a
// sample of users' scoped grants is confirmed against OpenFGA.
func (v *Verifier) Verify(ctx context.Context, tenants []string) (Report, error) {
	rep := Report{Tenants: len(tenants), Findings: []Finding{}}
	for _, tid := range tenants {
		s, err := v.load(ctx, tid)
		if err != nil {
			return rep, err
		}
		for _, r := range s.roles {
			for _, g := range sortedRefs(s.grants[r.ID]) {
				if !g.IsLegacy() {
					continue
				}
				mods := s.scopedBy[g.Short()]
				if len(mods) == 0 {
					rep.Findings = append(rep.Findings, Finding{Tenant: tid, Kind: FindingPending, Role: r.Slug, Permission: g.String()})
				}
				for _, m := range mods {
					if !s.grants[r.ID][g.WithModule(m)] {
						rep.Findings = append(rep.Findings, Finding{Tenant: tid, Kind: FindingLoss, Role: r.Slug, Permission: g.WithModule(m).String()})
					}
				}
			}
			if r.OriginOf() == store.OriginCustom && (r.Slug == "operator" || r.Slug == "auditor") {
				for _, g := range sortedRefs(s.grants[r.ID]) {
					if !g.IsLegacy() {
						rep.Findings = append(rep.Findings, Finding{Tenant: tid, Kind: FindingReview, Role: r.Slug, Permission: g.String()})
						break
					}
				}
			}
		}
		sample := v.SampleUsers
		if sample <= 0 {
			sample = 50
		}
		for i, uid := range sortedKeys(s.users) {
			eff := s.users[uid]
			var scoped []PermissionRef
			for _, g := range sortedRefs(eff) {
				if !g.IsLegacy() {
					scoped = append(scoped, g)
					continue
				}
				for _, m := range s.scopedBy[g.Short()] {
					if !eff[g.WithModule(m)] {
						rep.Findings = append(rep.Findings, Finding{Tenant: tid, Kind: FindingLoss, User: uid, Permission: g.WithModule(m).String()})
					}
				}
			}
			if i >= sample {
				continue
			}
			sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
			for start := 0; start < len(scoped); start += MaxTuplesPerWrite {
				chunk := scoped[start:min(start+MaxTuplesPerWrite, len(scoped))]
				held, err := v.authz.AllowedMany(sys, tid, uid, chunk)
				if err != nil {
					return rep, err
				}
				for j, ok := range held {
					if !ok {
						rep.Findings = append(rep.Findings, Finding{Tenant: tid, Kind: FindingDrift, User: uid, Permission: chunk[j].String()})
					}
				}
			}
		}
	}
	return rep, nil
}

// Snapshot records every active user's effective permissions (mirror rows,
// direct and through groups) for a later Compare.
func (v *Verifier) Snapshot(ctx context.Context, tenants []string) (Snapshot, error) {
	out := Snapshot{}
	for _, tid := range tenants {
		s, err := v.load(ctx, tid)
		if err != nil {
			return nil, err
		}
		users := map[string][]string{}
		for uid, eff := range s.users {
			refs := refsOf(sortedRefs(eff))
			if len(refs) > 0 {
				users[uid] = refs
			}
		}
		out[tid] = users
	}
	return out, nil
}

// Compare checks a snapshot against the current state: every permission a
// user held must still be held, a legacy one either as is or as the
// module-scoped permission of every module registering it (loss otherwise);
// anything else new is reported as a gain.
func (v *Verifier) Compare(ctx context.Context, before Snapshot) (Report, error) {
	rep := Report{Tenants: len(before), Findings: []Finding{}}
	for _, tid := range sortedKeys(before) {
		s, err := v.load(ctx, tid)
		if err != nil {
			return rep, err
		}
		users := before[tid]
		for _, uid := range sortedKeys(users) {
			had := map[PermissionRef]bool{}
			cur := s.users[uid]
			for _, str := range users[uid] {
				p, err := ParsePermissionRef(str)
				if err != nil {
					return rep, err
				}
				had[p] = true
				if cur[p] {
					continue
				}
				mods := s.scopedBy[p.Short()]
				covered := p.IsLegacy() && len(mods) > 0
				for _, m := range mods {
					covered = covered && cur[p.WithModule(m)]
				}
				if !covered {
					rep.Findings = append(rep.Findings, Finding{Tenant: tid, Kind: FindingLoss, User: uid, Permission: p.String()})
				}
			}
			for _, p := range sortedRefs(cur) {
				if had[p] || (!p.IsLegacy() && had[PermissionRef{Resource: p.Resource, Action: p.Action}]) {
					continue
				}
				rep.Findings = append(rep.Findings, Finding{Tenant: tid, Kind: FindingGain, User: uid, Permission: p.String()})
			}
		}
	}
	return rep, nil
}

// PruneResult counts what prune-legacy removed (or would remove).
type PruneResult struct {
	Tenants     int `json:"tenants"`
	Permissions int `json:"permissions"`
	Grants      int `json:"grants"`
}

// ErrPruneRefused is returned when verification is not clean.
var ErrPruneRefused = errors.New("authz: prune-legacy refused: verify is not clean")

// PruneLegacy removes the legacy permissions of every tenant once Verify is
// clean for all of them: tuples first (idempotent), then the rows and mirror
// grants; one permission_pruned event per tenant. dryRun only counts.
func (v *Verifier) PruneLegacy(ctx context.Context, tenants []string, dryRun bool) (PruneResult, error) {
	var res PruneResult
	rep, err := v.Verify(ctx, tenants)
	if err != nil {
		return res, err
	}
	if !rep.Clean() {
		return res, ErrPruneRefused
	}
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	for _, tid := range tenants {
		s, err := v.load(ctx, tid)
		if err != nil {
			return res, err
		}
		var removes []Tuple
		grants := 0
		for _, r := range s.roles {
			for _, g := range sortedRefs(s.grants[r.ID]) {
				if g.IsLegacy() {
					grants++
					removes = append(removes, GrantTuple(tid, r.Slug, g))
				}
			}
		}
		for _, p := range sortedRefs(s.legacy) {
			removes = append(removes, PermissionTenantTuple(tid, p))
		}
		res.Permissions += len(s.legacy)
		res.Grants += grants
		if len(s.legacy) == 0 && grants == 0 {
			continue
		}
		res.Tenants++
		if dryRun {
			continue
		}
		if err := v.authz.Write(sys, tid, nil, removes); err != nil {
			return res, err
		}
		if _, err := v.st.DeleteLegacyPermissions(ctx, tid); err != nil {
			return res, err
		}
		if v.audit != nil {
			_ = v.audit.Emit(audit.Event{Type: audit.PermissionPruned, TenantID: tid, ActorKind: "operator", Outcome: "ok", Reason: "cli_prune_legacy",
				Details: map[string]any{"count": len(s.legacy), "grants": grants}})
		}
	}
	return res, nil
}
