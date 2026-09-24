package memstore

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// Feature 016 state: directory connections and user directory links. Same
// semantics as store/directory.go: case-insensitive unique connection name
// per tenant, unique (tenant, connection, uid) link, connection delete sets
// the links' connection id to nil (SET NULL), user delete drops the link
// (CASCADE), and the imported-user writes only touch status "imported".

type directoryState struct {
	conns map[string]store.DirectoryConnection // by id
	links map[string]store.DirectoryLink       // by user id
}

func (m *Store) ds() *directoryState {
	if m.dir == nil {
		m.dir = &directoryState{conns: map[string]store.DirectoryConnection{}, links: map[string]store.DirectoryLink{}}
	}
	return m.dir
}

// injectedErr is the error FailNext arms for a method.
type injectedErr struct{ method string }

func (e injectedErr) Error() string { return "memstore: injected failure in " + e.method }

// FailNext arms the next call to the named directory method (e.g.
// "UpsertLink") to return an injected error without touching state.
func (m *Store) FailNext(method string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext == nil {
		m.failNext = map[string]bool{}
	}
	m.failNext[method] = true
}

// fail reports (and disarms) an injected failure for method. Caller holds mu.
func (m *Store) fail(method string) error {
	if m.failNext[method] {
		delete(m.failNext, method)
		return injectedErr{method}
	}
	return nil
}

func cloneConn(c store.DirectoryConnection) store.DirectoryConnection {
	c.BindPasswordEnc = append([]byte(nil), c.BindPasswordEnc...)
	return c
}

func (m *Store) nameTakenLocked(tid, id, name string) bool {
	for _, x := range m.ds().conns {
		if x.ID != id && x.TenantID == tid && strings.EqualFold(x.Name, name) {
			return true
		}
	}
	return false
}

// InsertDirectoryConnection creates a connection; a duplicate name
// (case-insensitive, per tenant) or id is ErrConflict.
func (m *Store) InsertDirectoryConnection(_ context.Context, c store.DirectoryConnection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("InsertDirectoryConnection"); err != nil {
		return err
	}
	s := m.ds()
	if _, exists := s.conns[c.ID]; exists || m.nameTakenLocked(c.TenantID, c.ID, c.Name) {
		return store.ErrConflict
	}
	c = cloneConn(c)
	c.UpdatedBy = c.CreatedBy
	c.LastTestAt, c.LastTestOutcome = nil, nil
	c.CreatedAt, c.UpdatedAt = m.Now(), m.Now()
	s.conns[c.ID] = c
	return nil
}

// GetDirectoryConnection by tenant + id.
func (m *Store) GetDirectoryConnection(_ context.Context, tid, id string) (store.DirectoryConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetDirectoryConnection"); err != nil {
		return store.DirectoryConnection{}, err
	}
	c, ok := m.ds().conns[id]
	if !ok || c.TenantID != tid {
		return store.DirectoryConnection{}, store.ErrNotFound
	}
	return cloneConn(c), nil
}

// GetDirectoryConnectionAnyTenant by id alone (system scope; cross-tenant
// refusal auditing only).
func (m *Store) GetDirectoryConnectionAnyTenant(_ context.Context, id string) (store.DirectoryConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetDirectoryConnectionAnyTenant"); err != nil {
		return store.DirectoryConnection{}, err
	}
	c, ok := m.ds().conns[id]
	if !ok {
		return store.DirectoryConnection{}, store.ErrNotFound
	}
	return cloneConn(c), nil
}

// ListDirectoryConnections of a tenant, by lower(name), id.
func (m *Store) ListDirectoryConnections(_ context.Context, tid string) ([]store.DirectoryConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListDirectoryConnections"); err != nil {
		return nil, err
	}
	var out []store.DirectoryConnection
	for _, c := range m.ds().conns {
		if c.TenantID == tid {
			out = append(out, cloneConn(c))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// CountDirectoryConnections of a tenant (max_connections_per_tenant cap).
func (m *Store) CountDirectoryConnections(_ context.Context, tid string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CountDirectoryConnections"); err != nil {
		return 0, err
	}
	n := 0
	for _, c := range m.ds().conns {
		if c.TenantID == tid {
			n++
		}
	}
	return n, nil
}

// UpdateDirectoryConnection rewrites the editable fields. An empty
// BindPasswordEnc keeps the stored password; test state, creator and
// creation time are untouched.
func (m *Store) UpdateDirectoryConnection(_ context.Context, c store.DirectoryConnection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpdateDirectoryConnection"); err != nil {
		return err
	}
	s := m.ds()
	old, ok := s.conns[c.ID]
	if !ok || old.TenantID != c.TenantID {
		return store.ErrNotFound
	}
	if m.nameTakenLocked(c.TenantID, c.ID, c.Name) {
		return store.ErrConflict
	}
	c = cloneConn(c)
	if len(c.BindPasswordEnc) == 0 {
		c.BindPasswordEnc = old.BindPasswordEnc
	}
	c.LastTestAt, c.LastTestOutcome = old.LastTestAt, old.LastTestOutcome
	c.CreatedBy, c.CreatedAt = old.CreatedBy, old.CreatedAt
	c.UpdatedAt = m.Now()
	s.conns[c.ID] = c
	return nil
}

// SetDirectoryConnectionTest records the outcome of a connection test.
func (m *Store) SetDirectoryConnectionTest(_ context.Context, tid, id, outcome string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("SetDirectoryConnectionTest"); err != nil {
		return err
	}
	s := m.ds()
	c, ok := s.conns[id]
	if !ok || c.TenantID != tid {
		return store.ErrNotFound
	}
	o, t := outcome, at
	c.LastTestOutcome, c.LastTestAt = &o, &t
	s.conns[id] = c
	return nil
}

// DeleteDirectoryConnection removes a connection; its links keep the
// connection_name snapshot and lose the connection id (ON DELETE SET NULL).
func (m *Store) DeleteDirectoryConnection(_ context.Context, tid, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteDirectoryConnection"); err != nil {
		return err
	}
	s := m.ds()
	c, ok := s.conns[id]
	if !ok || c.TenantID != tid {
		return store.ErrNotFound
	}
	delete(s.conns, id)
	for uid, l := range s.links {
		if l.ConnectionID != nil && *l.ConnectionID == id {
			l.ConnectionID = nil
			s.links[uid] = l
		}
	}
	return nil
}

// UsersByEmails returns the tenant's users for the given e-mails, keyed by
// the stored e-mail; matching is case-insensitive.
func (m *Store) UsersByEmails(_ context.Context, tid string, emails []string) (map[string]store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UsersByEmails"); err != nil {
		return nil, err
	}
	out := make(map[string]store.User, len(emails))
	for _, e := range emails {
		if u, ok := m.Users[key(tid, e)]; ok {
			out[u.Email] = u
		}
	}
	return out, nil
}

// LinksByUIDs returns the links of one connection for the given directory
// uids, keyed by uid.
func (m *Store) LinksByUIDs(_ context.Context, tid, connID string, uids []string) (map[string]store.DirectoryLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("LinksByUIDs"); err != nil {
		return nil, err
	}
	want := make(map[string]bool, len(uids))
	for _, u := range uids {
		want[u] = true
	}
	out := make(map[string]store.DirectoryLink, len(uids))
	for _, l := range m.ds().links {
		if l.TenantID == tid && l.ConnectionID != nil && *l.ConnectionID == connID && want[l.DirectoryUID] {
			out[l.DirectoryUID] = l
		}
	}
	return out, nil
}

// UpsertLink inserts a user's link or refreshes it on re-import
// (first_imported_at is kept). A uid already linked to another user of the
// same connection is ErrConflict; a missing user or connection is
// ErrNotFound (the SQL foreign keys refuse it).
func (m *Store) UpsertLink(_ context.Context, l store.DirectoryLink) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpsertLink"); err != nil {
		return err
	}
	s := m.ds()
	if _, _, ok := m.userByID(l.TenantID, l.UserID); !ok {
		return store.ErrNotFound
	}
	if l.ConnectionID != nil {
		if _, ok := s.conns[*l.ConnectionID]; !ok {
			return store.ErrNotFound
		}
		for uid, x := range s.links {
			if uid != l.UserID && x.TenantID == l.TenantID && x.ConnectionID != nil && *x.ConnectionID == *l.ConnectionID && x.DirectoryUID == l.DirectoryUID {
				return store.ErrConflict
			}
		}
	}
	if old, ok := s.links[l.UserID]; ok {
		l.FirstImportedAt = old.FirstImportedAt
	}
	s.links[l.UserID] = l
	return nil
}

// UpdateImportedUser refreshes e-mail and names of a user that is still
// imported; any other status (or a missing user) is ErrNotFound, and an
// e-mail already used in the tenant is ErrConflict.
func (m *Store) UpdateImportedUser(_ context.Context, tid, uid string, p store.ImportedProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpdateImportedUser"); err != nil {
		return err
	}
	k, u, ok := m.userByID(tid, uid)
	if !ok || u.Status != "imported" {
		return store.ErrNotFound
	}
	nk := key(tid, p.Email)
	if other, taken := m.Users[nk]; taken && other.ID != uid {
		return store.ErrConflict
	}
	u.Email, u.DisplayName, u.FirstName, u.LastName, u.DisplayNameExplicit = p.Email, p.DisplayName, p.FirstName, p.LastName, p.DisplayNameExplicit
	u.UpdatedAt = m.Now()
	delete(m.Users, k)
	m.Users[nk] = u
	return nil
}

// DeleteImportedUser hard-deletes a user only while imported; the link and
// the user's other rows go with it (ON DELETE CASCADE). Any other status (or
// a missing user) is ErrNotFound.
func (m *Store) DeleteImportedUser(_ context.Context, tid, uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteImportedUser"); err != nil {
		return err
	}
	k, u, ok := m.userByID(tid, uid)
	if !ok || u.Status != "imported" {
		return store.ErrNotFound
	}
	delete(m.Users, k)
	delete(m.ds().links, uid)
	uk := tid + "/" + uid
	delete(m.RoleMap, uk)
	delete(m.Bindings, uk)
	delete(m.Codes, uk)
	for id, s := range m.Sessions {
		if s.TenantID == tid && s.UserID == uid {
			delete(m.Sessions, id)
		}
	}
	if g := m.g; g != nil {
		for gid, ids := range g.members {
			var keep []string
			for _, x := range ids {
				if x != uid {
					keep = append(keep, x)
				}
			}
			g.members[gid] = keep
			delete(g.added, gid+"/"+uid)
		}
		delete(g.avatars, uid)
	}
	return nil
}

// pendingInvitationLocked is the id of the most recent pending (not accepted,
// not revoked; expired included) invitation for an invited user, as in
// store.ListUsers. The in-memory row has no created_at, so the latest expiry
// stands in for it. Caller holds mu.
func (m *Store) pendingInvitationLocked(u store.User) *string {
	if u.Status != "invited" {
		return nil
	}
	var best *store.Invitation
	for _, i := range m.Invitations {
		if i.TenantID != u.TenantID || !strings.EqualFold(i.Email, u.Email) || i.AcceptedAt != nil || i.RevokedAt != nil {
			continue
		}
		if best == nil || i.ExpiresAt.After(best.ExpiresAt) || (i.ExpiresAt.Equal(best.ExpiresAt) && i.ID < best.ID) {
			c := i
			best = &c
		}
	}
	if best == nil {
		return nil
	}
	id := best.ID
	return &id
}

// withOriginLocked fills the ListUsers-only fields (directory link, pending
// invitation id). Caller holds mu.
func (m *Store) withOriginLocked(u store.User) store.User {
	u.Directory, u.InvitationID = nil, m.pendingInvitationLocked(u)
	if m.dir != nil {
		if l, ok := m.dir.links[u.ID]; ok && l.TenantID == u.TenantID {
			u.Directory = &l
		}
	}
	return u
}
