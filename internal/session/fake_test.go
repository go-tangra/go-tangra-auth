package session

import (
	"context"
	"sync"
	"time"

	"github.com/go-freya/freya/services/auth/internal/store"
)

// fakeStore is an in-memory Store with the same semantics as the SQL.
type fakeStore struct {
	mu       sync.Mutex
	sessions map[string]*store.Session
	revs     []store.Revocation
	tenants  map[string]store.Tenant
	roles    map[string][]string
	users    map[string]store.User // tenant/user
	roleHits int                   // Roles() calls (session refresh tests)
	now      func() time.Time
}

func newFake(now func() time.Time) *fakeStore {
	return &fakeStore{sessions: map[string]*store.Session{}, tenants: map[string]store.Tenant{}, roles: map[string][]string{}, users: map[string]store.User{}, now: now}
}

func (f *fakeStore) Insert(_ context.Context, s store.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := s
	f.sessions[s.ID] = &c
	return nil
}
func (f *fakeStore) GetByHash(_ context.Context, hash []byte) (store.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions {
		if string(s.SecretHash) == string(hash) {
			return *s, nil
		}
	}
	return store.Session{}, store.ErrNotFound
}
func (f *fakeStore) Get(_ context.Context, tid, id string) (store.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sessions[id]; ok && s.TenantID == tid {
		return *s, nil
	}
	return store.Session{}, store.ErrNotFound
}
func (f *fakeStore) ListUser(_ context.Context, tid, uid string) ([]store.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.Session
	for _, s := range f.sessions {
		if s.TenantID == tid && s.UserID == uid {
			out = append(out, *s)
		}
	}
	return out, nil
}
func (f *fakeStore) Touch(_ context.Context, tid, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sessions[id]; ok && s.TenantID == tid {
		s.LastSeen = f.now()
	}
	return nil
}
func (f *fakeStore) revoke(id, reason string) {
	if s, ok := f.sessions[id]; ok && s.RevokedAt == nil {
		t := f.now()
		s.RevokedAt, s.RevokedReason = &t, &reason
	}
}
func (f *fakeStore) Revoke(_ context.Context, tid, id, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sessions[id]; !ok || s.TenantID != tid {
		return store.ErrNotFound
	}
	f.revoke(id, reason)
	return nil
}
func (f *fakeStore) RevokeUser(_ context.Context, tid, uid, reason, keep string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, s := range f.sessions {
		if s.TenantID == tid && s.UserID == uid && id != keep {
			f.revoke(id, reason)
		}
	}
	return nil
}
func (f *fakeStore) RevokeTenant(_ context.Context, tid, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, s := range f.sessions {
		if s.TenantID == tid {
			f.revoke(id, reason)
		}
	}
	return nil
}
func (f *fakeStore) InsertRevocation(_ context.Context, r store.Revocation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revs = append(f.revs, r)
	return nil
}
func (f *fakeStore) RevocationsSince(_ context.Context, since time.Time, limit int) ([]store.Revocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.Revocation
	for _, r := range f.revs {
		if r.TS.After(since) && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *fakeStore) Tenant(_ context.Context, tid string) (store.Tenant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tenants[tid]
	if !ok {
		return store.Tenant{}, store.ErrNotFound
	}
	return t, nil
}
func (f *fakeStore) Roles(_ context.Context, tid, uid string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roleHits++
	return f.roles[tid+"/"+uid], nil
}

func (f *fakeStore) User(_ context.Context, tid, uid string) (store.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[tid+"/"+uid]; ok {
		return u, nil
	}
	return store.User{ID: uid, TenantID: tid, Email: uid + "@x.test"}, nil
}
