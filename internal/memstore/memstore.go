// Package memstore is an in-memory implementation of the store-facing
// interfaces (session.Store, user.Store) for unit tests, fuzzing and
// single-process development. Semantics mirror the SQL repositories,
// including tenant scoping.
package memstore

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/permref"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// Attempt is one recorded sign-in attempt.
type Attempt struct {
	TenantID, UserID, EmailHash, IPHash, Outcome, Reason string
}

// Store holds everything in maps; exported fields are for test setup.
type Store struct {
	mu       sync.Mutex
	Tenants  map[string]store.Tenant // by id
	Users    map[string]store.User   // by tenant/email (lower-case)
	Sessions map[string]*store.Session
	Revs     []store.Revocation
	RoleMap  map[string][]string // tenant/user → slugs
	Attempts []Attempt
	Clients  map[string]store.ClientApplication
	// US2 state
	Invitations map[string]store.Invitation   // by id
	RoleRows    map[string]store.Role         // by id
	Bindings    map[string][]string           // tenant/user → role ids
	RolePerms   map[string][]permref.Ref      // role id → grants (feature 019: module-scoped)
	Permissions map[string][]store.Permission // tenant → catalogue
	Outbox      []store.OutboxItem
	Codes       map[string][]recoveryCode // tenant/user → codes
	Recoveries  map[string]store.RecoveryRequest
	Grants      map[string]store.OperatorGrant
	AuditRows   []store.AuditRow
	Now         func() time.Time
	g           *groupState                           // feature 004 (see groups.go)
	dir         *directoryState                       // feature 016 (see directory.go)
	failNext    map[string]bool                       // methods armed by FailNext (see directory.go)
	keys        map[string][]store.WebAuthnCredential // feature 018: tenant/user → keys (see webauthn.go)
	handles     map[string][]byte                     // tenant/user → WebAuthn user handle
	mods        *moduleState                          // feature 019 (see modules.go)
}

// New returns an empty store.
func New() *Store {
	return &Store{Tenants: map[string]store.Tenant{}, Users: map[string]store.User{}, Sessions: map[string]*store.Session{}, RoleMap: map[string][]string{}, Clients: map[string]store.ClientApplication{},
		Invitations: map[string]store.Invitation{}, RoleRows: map[string]store.Role{}, Bindings: map[string][]string{}, RolePerms: map[string][]permref.Ref{}, Permissions: map[string][]store.Permission{}, Codes: map[string][]recoveryCode{}, Recoveries: map[string]store.RecoveryRequest{}, Grants: map[string]store.OperatorGrant{}, Now: time.Now}
}

func key(tid, email string) string { return tid + "/" + strings.ToLower(email) }

// AddTenant / AddUser / SetRoles seed data.
func (m *Store) AddTenant(t store.Tenant) { m.mu.Lock(); defer m.mu.Unlock(); m.Tenants[t.ID] = t }
func (m *Store) AddUser(u store.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u.DisplayNameExplicit = store.DisplayNameExplicit(u) // same rule as InsertUser
	m.Users[key(u.TenantID, u.Email)] = u
}
func (m *Store) SetRoles(tid, uid string, roles []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RoleMap[tid+"/"+uid] = roles
}

// AddClient registers an OAuth client application.
func (m *Store) AddClient(c store.ClientApplication) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Clients[c.ClientID] = c
}

// Client implements oauth.ClientSource.
func (m *Store) Client(_ context.Context, id string) (store.ClientApplication, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.Clients[id]
	if !ok {
		return store.ClientApplication{}, store.ErrNotFound
	}
	return c, nil
}

type recoveryCode struct {
	hash string
	used bool
}

// --- mfa / password stores (US4) ---

func (m *Store) SetMFA(_ context.Context, tid, uid string, enabled bool, secretEnc []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, u, ok := m.userByID(tid, uid)
	if !ok {
		return store.ErrNotFound
	}
	u.MFAEnabled, u.MFASecretEnc, u.MFALastCounter = enabled, secretEnc, 0
	m.Users[k] = u
	return nil
}
func (m *Store) SetMFACounter(_ context.Context, tid, uid string, counter int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, u, ok := m.userByID(tid, uid)
	if !ok {
		return store.ErrNotFound
	}
	u.MFALastCounter = counter
	m.Users[k] = u
	return nil
}
func (m *Store) ReplaceRecoveryCodes(_ context.Context, tid, uid string, hashes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var codes []recoveryCode
	for _, h := range hashes {
		codes = append(codes, recoveryCode{hash: h})
	}
	m.Codes[tid+"/"+uid] = codes
	return nil
}
func (m *Store) ListRecoveryCodeHashes(_ context.Context, tid, uid string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, c := range m.Codes[tid+"/"+uid] {
		if !c.used {
			out = append(out, c.hash)
		}
	}
	return out, nil
}
func (m *Store) UseRecoveryCode(_ context.Context, tid, uid, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	codes := m.Codes[tid+"/"+uid]
	for i := range codes {
		if codes[i].hash == hash && !codes[i].used {
			codes[i].used = true
			return nil
		}
	}
	return store.ErrNotFound
}
func (m *Store) SetPassword(_ context.Context, tid, uid, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, u, ok := m.userByID(tid, uid)
	if !ok {
		return store.ErrNotFound
	}
	h := hash
	t := m.Now()
	u.PasswordHash, u.PasswordChangedAt = &h, &t
	m.Users[k] = u
	return nil
}
func (m *Store) InsertRecoveryRequest(_ context.Context, r store.RecoveryRequest, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Recoveries[r.ID] = r
	return nil
}
func (m *Store) PeekRecovery(_ context.Context, hash string) (store.RecoveryRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.Recoveries {
		if r.TokenHash == hash && r.UsedAt == nil && m.Now().Before(r.ExpiresAt) {
			return r, nil
		}
	}
	return store.RecoveryRequest{}, store.ErrNotFound
}
func (m *Store) UseRecoveryRequest(_ context.Context, hash string) (store.RecoveryRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, r := range m.Recoveries {
		if r.TokenHash == hash && r.UsedAt == nil && m.Now().Before(r.ExpiresAt) {
			t := m.Now()
			r.UsedAt = &t
			m.Recoveries[id] = r
			return r, nil
		}
	}
	return store.RecoveryRequest{}, store.ErrNotFound
}

// --- tenant / operator stores (US5) ---

func (m *Store) InsertTenant(_ context.Context, t store.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.Tenants {
		if x.Slug == t.Slug {
			return store.ErrConflict
		}
	}
	m.Tenants[t.ID] = t
	return nil
}
func (m *Store) ListTenants(_ context.Context) ([]store.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Tenant
	for _, t := range m.Tenants {
		out = append(out, t)
	}
	return out, nil
}
func (m *Store) UpdateTenantStatus(_ context.Context, id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Tenants[id]
	if !ok {
		return store.ErrNotFound
	}
	t.Status = status
	m.Tenants[id] = t
	return nil
}
func (m *Store) UpdateTenantPolicy(_ context.Context, id string, policy []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Tenants[id]
	if !ok {
		return store.ErrNotFound
	}
	t.Policy = policy
	m.Tenants[id] = t
	return nil
}
func (m *Store) InsertOperatorGrant(_ context.Context, g store.OperatorGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Grants[g.ID] = g
	return nil
}
func (m *Store) ActiveOperatorGrant(_ context.Context, operatorID, tid string) (store.OperatorGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.Grants {
		if g.OperatorUserID == operatorID && g.TenantID == tid && g.RevokedAt == nil && m.Now().Before(g.ExpiresAt) {
			return g, nil
		}
	}
	return store.OperatorGrant{}, store.ErrNotFound
}
func (m *Store) InsertClient(_ context.Context, c store.ClientApplication) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.Clients[c.ClientID]; exists {
		return store.ErrConflict
	}
	m.Clients[c.ClientID] = c
	return nil
}
func (m *Store) ListClients(_ context.Context, tid string) ([]store.ClientApplication, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.ClientApplication
	for _, c := range m.Clients {
		if c.TenantID == tid {
			out = append(out, c)
		}
	}
	return out, nil
}

// --- user.Store ---

func (m *Store) TenantBySlug(_ context.Context, slug string) (store.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.Tenants {
		if t.Slug == slug {
			return t, nil
		}
	}
	return store.Tenant{}, store.ErrNotFound
}

func (m *Store) UserByEmail(_ context.Context, tid, email string) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.Users[key(tid, email)]
	if !ok {
		return store.User{}, store.ErrNotFound
	}
	return u, nil
}

func (m *Store) TouchSignin(_ context.Context, tid, uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, u := range m.Users {
		if u.TenantID == tid && u.ID == uid {
			t := m.Now()
			u.LastSigninAt = &t
			m.Users[k] = u
		}
	}
	return nil
}

func (m *Store) SetPasswordHash(_ context.Context, tid, uid, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, u := range m.Users {
		if u.TenantID == tid && u.ID == uid {
			h := hash
			u.PasswordHash = &h
			m.Users[k] = u
		}
	}
	return nil
}

func (m *Store) Attempt(_ context.Context, tid, uid, emailHash, ipHash, outcome, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Attempts = append(m.Attempts, Attempt{tid, uid, emailHash, ipHash, outcome, reason})
	return nil
}

// --- session.Store ---

func (m *Store) Insert(_ context.Context, s store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := s
	m.Sessions[s.ID] = &c
	return nil
}
func (m *Store) GetByHash(_ context.Context, hash []byte) (store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.Sessions {
		if string(s.SecretHash) == string(hash) {
			return *s, nil
		}
	}
	return store.Session{}, store.ErrNotFound
}
func (m *Store) Get(_ context.Context, tid, id string) (store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.Sessions[id]; ok && s.TenantID == tid {
		return *s, nil
	}
	return store.Session{}, store.ErrNotFound
}
func (m *Store) ListUser(_ context.Context, tid, uid string) ([]store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Session
	for _, s := range m.Sessions {
		if s.TenantID == tid && s.UserID == uid {
			out = append(out, *s)
		}
	}
	return out, nil
}
func (m *Store) Touch(_ context.Context, tid, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.Sessions[id]; ok && s.TenantID == tid {
		s.LastSeen = m.Now()
	}
	return nil
}
func (m *Store) revoke(id, reason string) {
	if s, ok := m.Sessions[id]; ok && s.RevokedAt == nil {
		t := m.Now()
		s.RevokedAt, s.RevokedReason = &t, &reason
	}
}
func (m *Store) Revoke(_ context.Context, tid, id, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.Sessions[id]; !ok || s.TenantID != tid {
		return store.ErrNotFound
	}
	m.revoke(id, reason)
	return nil
}
func (m *Store) RevokeUser(_ context.Context, tid, uid, reason, keep string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.Sessions {
		if s.TenantID == tid && s.UserID == uid && id != keep {
			m.revoke(id, reason)
		}
	}
	return nil
}
func (m *Store) RevokeTenant(_ context.Context, tid, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.Sessions {
		if s.TenantID == tid {
			m.revoke(id, reason)
		}
	}
	return nil
}
func (m *Store) InsertRevocation(_ context.Context, r store.Revocation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Revs = append(m.Revs, r)
	return nil
}
func (m *Store) RevocationsSince(_ context.Context, since time.Time, limit int) ([]store.Revocation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Revocation
	for _, r := range m.Revs {
		if r.TS.After(since) && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *Store) Tenant(_ context.Context, tid string) (store.Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Tenants[tid]
	if !ok {
		return store.Tenant{}, store.ErrNotFound
	}
	return t, nil
}
func (m *Store) Roles(_ context.Context, tid, uid string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.effectiveSlugsLocked(tid, uid), nil
}

// --- invite / admin / authz stores (US2) ---

// Atomic runs fn against the store; the in-memory store has no transactions.
func (m *Store) Atomic(_ context.Context, _ store.Scope, fn func(any) error) error { return fn(m) }

func (m *Store) AddRole(r store.Role) { m.mu.Lock(); defer m.mu.Unlock(); m.RoleRows[r.ID] = r }

func (m *Store) userByID(tid, uid string) (string, store.User, bool) {
	for k, u := range m.Users {
		if u.TenantID == tid && u.ID == uid {
			return k, u, true
		}
	}
	return "", store.User{}, false
}

func (m *Store) User(_ context.Context, tid, uid string) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, u, ok := m.userByID(tid, uid); ok {
		return u, nil
	}
	return store.User{}, store.ErrNotFound
}

// UserByID is User under the name the invite Tx uses (feature 016).
func (m *Store) UserByID(ctx context.Context, tid, uid string) (store.User, error) {
	return m.User(ctx, tid, uid)
}

// UserAnyTenant finds a user id across tenants (system scope; used only to
// audit cross-tenant attempts).
func (m *Store) UserAnyTenant(_ context.Context, uid string) (store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.Users {
		if u.ID == uid {
			return u, nil
		}
	}
	return store.User{}, store.ErrNotFound
}

func (m *Store) ListUsers(_ context.Context, tid, q, status string, limit int) ([]store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.User
	for _, u := range m.Users {
		if u.TenantID != tid || (status != "" && u.Status != status) || (q != "" && !strings.Contains(strings.ToLower(u.Email+" "+u.DisplayName+" "+u.FirstName+" "+u.LastName), strings.ToLower(q))) {
			continue
		}
		out = append(out, m.withOriginLocked(u))
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *Store) InsertUser(_ context.Context, u store.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.Users[key(u.TenantID, u.Email)]; exists {
		return store.ErrConflict
	}
	m.Users[key(u.TenantID, u.Email)] = u
	return nil
}

func (m *Store) UpdateUserStatus(_ context.Context, tid, uid, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, u, ok := m.userByID(tid, uid)
	if !ok {
		return store.ErrNotFound
	}
	u.Status = status
	m.Users[k] = u
	return nil
}

func (m *Store) InsertInvitation(_ context.Context, i store.Invitation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Invitations[i.ID] = i
	return nil
}
func (m *Store) Invitation(_ context.Context, tid, id string) (store.Invitation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i, ok := m.Invitations[id]; ok && i.TenantID == tid {
		return i, nil
	}
	return store.Invitation{}, store.ErrNotFound
}
func (m *Store) InvitationByHash(_ context.Context, hash string) (store.Invitation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, i := range m.Invitations {
		if i.TokenHash == hash {
			return i, nil
		}
	}
	return store.Invitation{}, store.ErrNotFound
}
func (m *Store) RotateInvitation(_ context.Context, tid, id, hash string, exp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.Invitations[id]
	if !ok || i.TenantID != tid {
		return store.ErrNotFound
	}
	i.TokenHash, i.ExpiresAt = hash, exp
	m.Invitations[id] = i
	return nil
}
func (m *Store) MarkInvitationAccepted(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.Invitations[id]
	if !ok {
		return store.ErrNotFound
	}
	t := m.Now()
	i.AcceptedAt = &t
	m.Invitations[id] = i
	return nil
}

func (m *Store) InsertRole(_ context.Context, r store.Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.RoleRows {
		if x.TenantID == r.TenantID && x.Slug == r.Slug {
			return store.ErrConflict
		}
	}
	m.RoleRows[r.ID] = r
	return nil
}
func (m *Store) Role(_ context.Context, tid, id string) (store.Role, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.RoleRows[id]; ok && r.TenantID == tid {
		return r, nil
	}
	return store.Role{}, store.ErrNotFound
}
func (m *Store) UpdateRoleName(_ context.Context, tid, id, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.RoleRows[id]
	if !ok || r.TenantID != tid {
		return store.ErrNotFound
	}
	if r.OriginOf() != store.OriginCustom {
		return nil // like the SQL: only custom roles are renamed
	}
	r.DisplayName = name
	m.RoleRows[id] = r
	return nil
}
func (m *Store) RemoveRole(_ context.Context, tid, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.RoleRows[id]
	if !ok || r.TenantID != tid || r.OriginOf() != store.OriginCustom {
		return store.ErrNotFound
	}
	keep := map[string]store.Role{}
	for k, v := range m.RoleRows {
		if k != id {
			keep[k] = v
		}
	}
	m.RoleRows = keep
	delete(m.RolePerms, id)
	for k, ids := range m.Bindings {
		var out []string
		for _, x := range ids {
			if x != id {
				out = append(out, x)
			}
		}
		m.Bindings[k] = out
	}
	return nil
}
func (m *Store) ReplaceRolePermissions(_ context.Context, tid, rid string, perms []permref.Ref) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ReplaceRolePermissions"); err != nil {
		return err
	}
	if r, ok := m.RoleRows[rid]; !ok || r.TenantID != tid {
		return store.ErrNotFound
	}
	seen := map[permref.Ref]bool{}
	var out []permref.Ref
	for _, p := range perms {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sortRefs(out)
	m.RolePerms[rid] = out
	return nil
}
func (m *Store) RoleAssignees(_ context.Context, tid, rid string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k, ids := range m.Bindings {
		if !strings.HasPrefix(k, tid+"/") {
			continue
		}
		for _, x := range ids {
			if x == rid {
				out = append(out, strings.TrimPrefix(k, tid+"/"))
			}
		}
	}
	return out, nil
}
func (m *Store) UpsertPermission(_ context.Context, tid string, p store.Permission, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, x := range m.Permissions[tid] {
		if x.Ref() == p.Ref() {
			m.Permissions[tid][i].Description = p.Description
			return nil
		}
	}
	m.Permissions[tid] = append(m.Permissions[tid], p)
	return nil
}
func (m *Store) ListPermissions(_ context.Context, tid string) ([]store.Permission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]store.Permission(nil), m.Permissions[tid]...)
	sort.Slice(out, func(i, j int) bool { return lessRef(out[i].Ref(), out[j].Ref()) })
	return out, nil
}

// DeleteLegacyPermissions drops a tenant's legacy rows and mirror grants.
func (m *Store) DeleteLegacyPermissions(_ context.Context, tid string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var keep []store.Permission
	var n int64
	for _, p := range m.Permissions[tid] {
		if p.Module == "" {
			n++
			continue
		}
		keep = append(keep, p)
	}
	m.Permissions[tid] = keep
	for id, r := range m.RoleRows {
		if r.TenantID != tid {
			continue
		}
		var grants []permref.Ref
		for _, g := range m.RolePerms[id] {
			if !g.IsLegacy() {
				grants = append(grants, g)
			}
		}
		m.RolePerms[id] = grants
	}
	return n, nil
}

func lessRef(a, b permref.Ref) bool {
	if a.Module != b.Module {
		return a.Module < b.Module
	}
	if a.Resource != b.Resource {
		return a.Resource < b.Resource
	}
	return a.Action < b.Action
}

func sortRefs(refs []permref.Ref) {
	sort.Slice(refs, func(i, j int) bool { return lessRef(refs[i], refs[j]) })
}

func (m *Store) UserStatus(_ context.Context, tid, uid string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, u, ok := m.userByID(tid, uid); ok {
		return u.Status, nil
	}
	return "", store.ErrNotFound
}
func (m *Store) TenantStatus(_ context.Context, tid string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.Tenants[tid]
	if !ok {
		return "", store.ErrNotFound
	}
	return t.Status, nil
}

func (m *Store) RolesByID(_ context.Context, tid string, ids []string) ([]store.Role, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Role
	for _, id := range ids {
		r, ok := m.RoleRows[id]
		if !ok || r.TenantID != tid {
			return nil, store.ErrNotFound
		}
		out = append(out, r)
	}
	return out, nil
}
func (m *Store) ListRoles(_ context.Context, tid string) ([]store.Role, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Role
	for _, r := range m.RoleRows {
		if r.TenantID == tid {
			out = append(out, r)
		}
	}
	// Like the SQL: built-in first, then by slug.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Builtin != out[j].Builtin {
			return out[i].Builtin
		}
		return out[i].Slug < out[j].Slug
	})
	return out, nil
}
func (m *Store) UserRoles(_ context.Context, tid, uid string) ([]store.Role, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Role
	for _, id := range m.Bindings[tid+"/"+uid] {
		if r, ok := m.RoleRows[id]; ok && r.TenantID == tid {
			out = append(out, r)
		}
	}
	return out, nil
}
func (m *Store) RolePermissions(_ context.Context, tid, roleID string) ([]permref.Ref, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.RoleRows[roleID]; !ok || r.TenantID != tid {
		return nil, store.ErrNotFound
	}
	return append([]permref.Ref(nil), m.RolePerms[roleID]...), nil
}
func (m *Store) ReplaceBindings(_ context.Context, tid, uid, _ string, roleIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Bindings[tid+"/"+uid] = append([]string(nil), roleIDs...)
	return nil
}
func (m *Store) CountWithRole(_ context.Context, tid, slug string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, ids := range m.Bindings {
		if !strings.HasPrefix(k, tid+"/") {
			continue
		}
		for _, id := range ids {
			if r, ok := m.RoleRows[id]; ok && r.Slug == slug {
				n++
			}
		}
	}
	return n, nil
}

func (m *Store) Enqueue(_ context.Context, it store.OutboxItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Outbox = append(m.Outbox, it)
	return nil
}

func (m *Store) InsertAuditRows(_ context.Context, rows []store.AuditRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AuditRows = append(m.AuditRows, rows...)
	return nil
}

func (m *Store) QueryAudit(_ context.Context, tid, userID, eventType string, from, to, cursor time.Time, limit int) ([]store.AuditRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.AuditRow
	for i := len(m.AuditRows) - 1; i >= 0; i-- {
		r := m.AuditRows[i]
		if r.TenantID != tid || (eventType != "" && r.EventType != eventType) || (userID != "" && (r.ActorUserID == nil || *r.ActorUserID != userID)) {
			continue
		}
		if (!from.IsZero() && r.TS.Before(from)) || (!to.IsZero() && r.TS.After(to)) || (!cursor.IsZero() && !r.TS.Before(cursor)) {
			continue
		}
		out = append(out, r)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}
