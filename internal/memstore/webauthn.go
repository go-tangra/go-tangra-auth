package memstore

import (
	"bytes"
	"context"
	"strings"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// Security keys (feature 018). Semantics mirror internal/store/webauthn.go:
// credential ids are unique globally, names per user (case-insensitive).

func (m *Store) keysOf(tid, uid string) []store.WebAuthnCredential {
	if m.keys == nil {
		m.keys = map[string][]store.WebAuthnCredential{}
		m.handles = map[string][]byte{}
	}
	return m.keys[tid+"/"+uid]
}

// WebAuthnHandle returns the user's handle (nil before the first key).
func (m *Store) WebAuthnHandle(_ context.Context, tid, uid string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, _, ok := m.userByID(tid, uid); !ok {
		return nil, store.ErrNotFound
	}
	m.keysOf(tid, uid)
	return m.handles[tid+"/"+uid], nil
}

// EnsureWebAuthnHandle stores candidate unless a handle exists.
func (m *Store) EnsureWebAuthnHandle(_ context.Context, tid, uid string, candidate []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, _, ok := m.userByID(tid, uid); !ok {
		return nil, store.ErrNotFound
	}
	m.keysOf(tid, uid)
	if h := m.handles[tid+"/"+uid]; h != nil {
		return h, nil
	}
	m.handles[tid+"/"+uid] = append([]byte(nil), candidate...)
	return m.handles[tid+"/"+uid], nil
}

// ListWebAuthnCredentials returns copies of the user's keys, oldest first.
func (m *Store) ListWebAuthnCredentials(_ context.Context, tid, uid string) ([]store.WebAuthnCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.WebAuthnCredential(nil), m.keysOf(tid, uid)...), nil
}

// InsertWebAuthnCredential stores a key.
func (m *Store) InsertWebAuthnCredential(_ context.Context, c store.WebAuthnCredential) error { //nolint:gocritic // mirrors store.InsertWebAuthnCredential
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, list := range m.keys {
		for _, k := range list {
			if bytes.Equal(k.CredentialID, c.CredentialID) {
				return store.ErrCredentialExists
			}
		}
	}
	for _, k := range m.keysOf(c.TenantID, c.UserID) {
		if strings.EqualFold(k.Name, c.Name) {
			return store.ErrConflict
		}
	}
	c.CreatedAt = m.Now()
	m.keys[c.TenantID+"/"+c.UserID] = append(m.keys[c.TenantID+"/"+c.UserID], c)
	return nil
}

func (m *Store) updateKey(tid, uid, id string, fn func(*store.WebAuthnCredential) error) error {
	for owner, list := range m.keys {
		if !strings.HasPrefix(owner, tid+"/") || (uid != "" && owner != tid+"/"+uid) {
			continue
		}
		for i := range list {
			if list[i].ID == id {
				return fn(&list[i])
			}
		}
	}
	return store.ErrNotFound
}

// RenameWebAuthnCredential renames one of the user's keys.
func (m *Store) RenameWebAuthnCredential(_ context.Context, tid, uid, id, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.keysOf(tid, uid) {
		if k.ID != id && strings.EqualFold(k.Name, name) {
			return store.ErrConflict
		}
	}
	return m.updateKey(tid, uid, id, func(k *store.WebAuthnCredential) error { k.Name = name; return nil })
}

// DeleteWebAuthnCredential removes one of the user's keys.
func (m *Store) DeleteWebAuthnCredential(_ context.Context, tid, uid, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.keysOf(tid, uid)
	for i, k := range list {
		if k.ID == id {
			m.keys[tid+"/"+uid] = append(list[:i:i], list[i+1:]...)
			return nil
		}
	}
	return store.ErrNotFound
}

// UpdateWebAuthnUse records a successful assertion.
func (m *Store) UpdateWebAuthnUse(_ context.Context, tid, id string, signCount int64, backupState bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keysOf(tid, "")
	return m.updateKey(tid, "", id, func(k *store.WebAuthnCredential) error {
		now := m.Now()
		k.SignCount, k.BackupState, k.LastUsedAt = signCount, backupState, &now
		return nil
	})
}

// FlagWebAuthnClone marks a key as possibly cloned.
func (m *Store) FlagWebAuthnClone(_ context.Context, tid, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keysOf(tid, "")
	return m.updateKey(tid, "", id, func(k *store.WebAuthnCredential) error {
		if k.CloneFlaggedAt == nil {
			now := m.Now()
			k.CloneFlaggedAt = &now
		}
		return nil
	})
}

// ResetMFA removes every second factor of a user.
func (m *Store) ResetMFA(_ context.Context, tid, uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, u, ok := m.userByID(tid, uid)
	if !ok {
		return store.ErrNotFound
	}
	u.MFAEnabled, u.MFASecretEnc, u.MFALastCounter = false, nil, 0
	m.Users[k] = u
	delete(m.Codes, tid+"/"+uid)
	m.keysOf(tid, uid)
	delete(m.keys, tid+"/"+uid)
	return nil
}
