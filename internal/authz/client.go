package authz

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Tuple is one relationship.
type Tuple struct{ User, Relation, Object string }

// Backend is the subset of OpenFGA the service uses (SDK-backed or Fake).
type Backend interface {
	Check(ctx context.Context, t Tuple) (bool, error)
	BatchCheck(ctx context.Context, ts []Tuple) ([]bool, error)
	// Write applies adds and removes atomically; removing a missing tuple is not an error.
	Write(ctx context.Context, adds, removes []Tuple) error
	// EnsureStore returns the id of the named store, creating it when absent.
	EnsureStore(ctx context.Context, name string) (string, error)
	// EnsureModel writes the authorization model when the latest one differs.
	EnsureModel(ctx context.Context) (string, error)
}

// DecisionTTL bounds how long a cached decision may be served (FR: ≤2 s).
const DecisionTTL = 2 * time.Second

// ErrCrossTenant is returned before any backend call when an object belongs
// to a tenant other than the requested one.
var ErrCrossTenant = errors.New("authz: cross-tenant object refused")

// Client wraps a Backend with tenant guards and the decision cache.
type Client struct {
	b     Backend
	cache *cache.Cache
	guard tenantctx.Guard
}

// New wraps b. cache may be nil (no decision cache).
func New(b Backend, c *cache.Cache, onRefusal func(tenantctx.Refusal)) *Client {
	return &Client{b: b, cache: c, guard: tenantctx.Guard{OnRefusal: onRefusal}}
}

// Guard returns the tenant guard (shared refusal auditing).
func (c *Client) Guard() tenantctx.Guard { return c.guard }

// Bootstrap ensures the store and model exist (idempotent).
func Bootstrap(ctx context.Context, b Backend, storeName string) (storeID, modelID string, err error) {
	if storeID, err = b.EnsureStore(ctx, storeName); err != nil {
		return "", "", err
	}
	if modelID, err = b.EnsureModel(ctx); err != nil {
		return "", "", err
	}
	return storeID, modelID, nil
}

func (c *Client) scoped(ctx context.Context, tid string, objects ...string) error {
	if err := c.guard.Require(ctx, tid); err != nil {
		return err
	}
	for _, o := range objects {
		ot, err := ObjectTenant(o)
		if err != nil {
			return err
		}
		if ot != tid {
			return ErrCrossTenant
		}
	}
	return nil
}

// Allowed reports whether user uid holds permission p in tenant tid.
func (c *Client) Allowed(ctx context.Context, tid, uid string, p PermissionRef) (bool, error) {
	obj := PermissionObject(tid, p)
	if err := c.scoped(ctx, tid, obj); err != nil {
		return false, err
	}
	key, err := c.decisionKey(ctx, tid, uid, p.String())
	if err == nil && key != "" {
		if v, ok, _ := c.cache.KV().Get(ctx, key); ok {
			return v == "1", nil
		}
	}
	ok, err := c.b.Check(ctx, Tuple{User: UserObject(uid), Relation: "granted", Object: obj})
	if err != nil {
		return false, err
	}
	if key != "" {
		_ = c.cache.KV().Set(ctx, key, boolStr(ok), DecisionTTL)
	}
	return ok, nil
}

// AllowedMany evaluates several permissions for one user in one tenant.
func (c *Client) AllowedMany(ctx context.Context, tid, uid string, ps []PermissionRef) ([]bool, error) {
	ts := make([]Tuple, len(ps))
	objs := make([]string, len(ps))
	for i, p := range ps {
		objs[i] = PermissionObject(tid, p)
		ts[i] = Tuple{User: UserObject(uid), Relation: "granted", Object: objs[i]}
	}
	if err := c.scoped(ctx, tid, objs...); err != nil {
		return nil, err
	}
	return c.b.BatchCheck(ctx, ts)
}

// IsMember reports tenant membership (owner/admin/member).
func (c *Client) IsMember(ctx context.Context, tid, uid string) (bool, error) {
	if err := c.scoped(ctx, tid); err != nil {
		return false, err
	}
	return c.b.Check(ctx, Tuple{User: UserObject(uid), Relation: "member", Object: TenantObject(tid)})
}

// Write applies tuple changes scoped to tid and invalidates its decisions.
func (c *Client) Write(ctx context.Context, tid string, adds, removes []Tuple) error {
	objs := make([]string, 0, len(adds)+len(removes))
	for _, t := range append(append([]Tuple{}, adds...), removes...) {
		objs = append(objs, t.Object)
		if ot, err := ObjectTenant(t.Object); err == nil && t.Relation == "tenant" && t.User != TenantObject(ot) {
			return ErrCrossTenant
		}
	}
	if err := c.scoped(ctx, tid, objs...); err != nil {
		return err
	}
	if err := c.b.Write(ctx, adds, removes); err != nil {
		return err
	}
	if c.cache != nil {
		_, _ = c.cache.BumpTenantVersion(ctx, tid)
	}
	return nil
}

// Convenience tuple constructors.
func MembershipTuple(tid, uid, relation string) Tuple {
	return Tuple{User: UserObject(uid), Relation: relation, Object: TenantObject(tid)}
}
func RoleTenantTuple(tid, slug string) Tuple {
	return Tuple{User: TenantObject(tid), Relation: "tenant", Object: RoleObject(tid, slug)}
}
func RoleAssignmentTuple(tid, slug, uid string) Tuple {
	return Tuple{User: UserObject(uid), Relation: "assignee", Object: RoleObject(tid, slug)}
}

// Group tuples (feature 004).
func GroupTenantTuple(tid, gid string) Tuple {
	return Tuple{User: TenantObject(tid), Relation: "tenant", Object: GroupObject(tid, gid)}
}
func GroupMembershipTuple(tid, gid, uid string) Tuple {
	return Tuple{User: UserObject(uid), Relation: "member", Object: GroupObject(tid, gid)}
}
func GroupRoleTuple(tid, gid, slug string) Tuple {
	return Tuple{User: GroupMembers(tid, gid), Relation: "assignee", Object: RoleObject(tid, slug)}
}
func PermissionTenantTuple(tid string, p PermissionRef) Tuple {
	return Tuple{User: TenantObject(tid), Relation: "tenant", Object: PermissionObject(tid, p)}
}
func GrantTuple(tid, slug string, p PermissionRef) Tuple {
	return Tuple{User: RoleAssignees(tid, slug), Relation: "granted", Object: PermissionObject(tid, p)}
}

func (c *Client) decisionKey(ctx context.Context, tid, uid, perm string) (string, error) {
	if c.cache == nil {
		return "", nil
	}
	v, err := c.cache.TenantVersion(ctx, tid)
	if err != nil {
		return "", err
	}
	return cache.DecisionKey(tid, uid, perm+"@"+strconv.FormatInt(v, 10)), nil
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Fake is an in-memory Backend implementing the model's semantics for tests
// and single-process development (direct tuples plus the role#assignee userset
// and tenant owner⊂admin⊂member hierarchy).
type Fake struct {
	mu     sync.Mutex
	tuples map[Tuple]struct{}
	Stores map[string]string
	Models int
}

// NewFake returns an empty fake.
func NewFake() *Fake { return &Fake{tuples: map[Tuple]struct{}{}, Stores: map[string]string{}} }

func (f *Fake) Check(_ context.Context, t Tuple) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.check(t), nil
}

func (f *Fake) check(t Tuple) bool {
	if _, ok := f.tuples[t]; ok {
		return true
	}
	switch t.Relation {
	case "member":
		// tenant member ⊃ admin; group member is a direct tuple only.
		if strings.HasPrefix(t.Object, "tenant:") {
			return f.check(Tuple{t.User, "admin", t.Object})
		}
	case "admin":
		return f.check(Tuple{t.User, "owner", t.Object})
	case "assignee":
		// role#assignee: [user, group#member] — walk the group userset.
		for k := range f.tuples {
			if k.Object == t.Object && k.Relation == "assignee" {
				if group, ok := cutSuffix(k.User, "#member"); ok && f.check(Tuple{t.User, "member", group}) {
					return true
				}
			}
		}
	case "granted":
		for k := range f.tuples {
			if k.Object == t.Object && k.Relation == "granted" {
				if role, ok := cutSuffix(k.User, "#assignee"); ok && f.check(Tuple{t.User, "assignee", role}) {
					return true
				}
			}
		}
	}
	return false
}

func cutSuffix(s, suf string) (string, bool) {
	if len(s) >= len(suf) && s[len(s)-len(suf):] == suf {
		return s[:len(s)-len(suf)], true
	}
	return s, false
}

func (f *Fake) BatchCheck(ctx context.Context, ts []Tuple) ([]bool, error) {
	out := make([]bool, len(ts))
	for i, t := range ts {
		out[i], _ = f.Check(ctx, t)
	}
	return out, nil
}

func (f *Fake) Write(_ context.Context, adds, removes []Tuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range adds {
		if _, err := ObjectTenant(t.Object); err != nil {
			return fmt.Errorf("fake fga: %w", err)
		}
		f.tuples[t] = struct{}{}
	}
	for _, t := range removes {
		delete(f.tuples, t)
	}
	return nil
}

func (f *Fake) EnsureStore(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.Stores[name]; ok {
		return id, nil
	}
	id := "store-" + strconv.Itoa(len(f.Stores)+1)
	f.Stores[name] = id
	return id, nil
}

func (f *Fake) EnsureModel(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Models == 0 {
		f.Models++
	}
	return "model-1", nil
}

// Len returns the number of stored tuples.
func (f *Fake) Len() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.tuples) }
