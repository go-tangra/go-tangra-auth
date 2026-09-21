// Package session manages browser sessions: creation, resolution from the
// cookie secret, idle/absolute expiry, revocation with fan-out (Valkey marks,
// revocations hypertable, pub/sub) and the revocation feed.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenant"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// Revocation reasons (closed vocabulary shared with the feed).
const (
	ReasonSignout     = "signout"
	ReasonUserRevoked = "user_revoked"
	ReasonAdmin       = "admin_revoked"
	ReasonPassword    = "password_changed"
	ReasonDeactivated = "user_deactivated"
	ReasonSuspended   = "tenant_suspended"
	ReasonIdle        = "idle_timeout"
	ReasonExpired     = "expired"
)

// RevocationRetention is how long feed entries and marks live (> max token life).
const RevocationRetention = 60 * time.Minute

// ErrNoSession means the cookie does not map to a live session.
var ErrNoSession = errors.New("session: no live session")

// Store is the persistence the manager needs (database or fake).
type Store interface {
	Insert(ctx context.Context, s store.Session) error
	GetByHash(ctx context.Context, hash []byte) (store.Session, error)
	Get(ctx context.Context, tenantID, id string) (store.Session, error)
	ListUser(ctx context.Context, tenantID, userID string) ([]store.Session, error)
	Touch(ctx context.Context, tenantID, id string) error
	Revoke(ctx context.Context, tenantID, id, reason string) error
	RevokeUser(ctx context.Context, tenantID, userID, reason, keepID string) error
	RevokeTenant(ctx context.Context, tenantID, reason string) error
	InsertRevocation(ctx context.Context, r store.Revocation) error
	RevocationsSince(ctx context.Context, since time.Time, limit int) ([]store.Revocation, error)
	Tenant(ctx context.Context, tenantID string) (store.Tenant, error)
	Roles(ctx context.Context, tenantID, userID string) ([]string, error) // effective roles (direct ∪ groups)
	User(ctx context.Context, tenantID, userID string) (store.User, error)
}

// Manager implements httpapi.SessionResolver and the revocation fan-out.
type Manager struct {
	st    Store
	cache *cache.Cache
	audit *audit.Writer
	now   func() time.Time
}

// New wires the manager; audit may be nil.
func New(st Store, c *cache.Cache, a *audit.Writer) *Manager {
	return &Manager{st: st, cache: c, audit: a, now: time.Now}
}

// view is the cached session projection (sess:<hash>).
type view struct {
	ID, TenantID, UserID string
	Roles, AMR           []string
	Operator             bool
	CreatedAt, LastSeen  time.Time
	ExpiresAt            time.Time
	Idle                 time.Duration
	// PolicyVersion is the tenant version the roles were loaded at; drift
	// (a role or group change) triggers a reload on the next resolve.
	PolicyVersion int64
	DisplayName   string
	AvatarURL     string
}

// CreateParams describe a new session.
type CreateParams struct {
	TenantID, UserID  string
	Roles, AMR        []string
	Operator          bool
	IPHash, UserAgent string
	Policy            tenant.Policy
}

// Create stores a session and returns the cookie secret (never persisted).
func (m *Manager) Create(ctx context.Context, p CreateParams) (store.Session, string, error) {
	secret, err := crypto.RandomToken(32)
	if err != nil {
		return store.Session{}, "", err
	}
	now := m.now()
	s := store.Session{ID: store.NewID(), TenantID: p.TenantID, UserID: p.UserID, SecretHash: []byte(crypto.HashToken(secret)), AMR: nonNil(p.AMR),
		CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(p.Policy.SessionLifetime.D()), IPHash: p.IPHash, UserAgent: clip(p.UserAgent, 256)}
	if err := m.st.Insert(ctx, s); err != nil {
		return store.Session{}, "", err
	}
	v := view{ID: s.ID, TenantID: s.TenantID, UserID: s.UserID, Roles: nonNil(p.Roles), AMR: s.AMR, Operator: p.Operator, CreatedAt: now, LastSeen: now, ExpiresAt: s.ExpiresAt, Idle: p.Policy.IdleTimeout.D()}
	v.PolicyVersion = m.tenantVersion(ctx, s.TenantID)
	m.loadProfile(ctx, &v)
	m.putView(ctx, string(s.SecretHash), v)
	return s, secret, nil
}

// tenantVersion reads the tenant's policy version (0 without a cache).
func (m *Manager) tenantVersion(ctx context.Context, tid string) int64 {
	if m.cache == nil {
		return 0
	}
	v, _ := m.cache.TenantVersion(ctx, tid)
	return v
}

// loadProfile fills the display attributes from the user row; a missing row
// leaves them empty rather than failing the session.
func (m *Manager) loadProfile(ctx context.Context, v *view) {
	u, err := m.st.User(ctx, v.TenantID, v.UserID)
	if err != nil {
		return
	}
	v.DisplayName = u.DisplayName
	v.AvatarURL = tenantctx.AvatarURL(u.ID, u.AvatarID)
}

// refreshIfStale reloads effective roles and the profile when the tenant's
// policy version moved since the view was built. Returns the (possibly
// updated) view and whether it changed.
func (m *Manager) refreshIfStale(ctx context.Context, v view) (view, bool) {
	cur := m.tenantVersion(ctx, v.TenantID)
	if cur == v.PolicyVersion {
		return v, false
	}
	roles, err := m.st.Roles(ctx, v.TenantID, v.UserID)
	if err != nil {
		return v, false
	}
	v.Roles = nonNil(roles)
	v.PolicyVersion = cur
	m.loadProfile(ctx, &v)
	return v, true
}

// RefreshUser evicts every cached view of a user so the next resolve reloads
// roles and profile (profile edits; the tenant version is untouched).
func (m *Manager) RefreshUser(ctx context.Context, tenantID, userID string) {
	if m.cache == nil {
		return
	}
	sessions, err := m.st.ListUser(ctx, tenantID, userID)
	if err != nil {
		return
	}
	for _, s := range sessions {
		m.evictView(ctx, string(s.SecretHash))
	}
}

func (m *Manager) putView(ctx context.Context, hash string, v view) {
	if m.cache == nil {
		return
	}
	b, _ := json.Marshal(v)
	ttl := v.Idle
	if rem := v.ExpiresAt.Sub(m.now()); rem < ttl {
		ttl = rem
	}
	if ttl > 0 {
		_ = m.cache.KV().Set(ctx, cache.SessionKey(hash), string(b), ttl)
	}
}

// Resolve turns a cookie secret into an actor, enforcing revocation marks,
// absolute and idle expiry, and touching last-seen at most once a minute.
func (m *Manager) Resolve(ctx context.Context, secret string) (tenantctx.Actor, error) {
	if secret == "" {
		return tenantctx.Actor{}, ErrNoSession
	}
	hash := crypto.HashToken(secret)
	now := m.now()
	v, ok := m.getView(ctx, hash)
	if !ok {
		s, err := m.st.GetByHash(ctx, []byte(hash))
		if err != nil || s.RevokedAt != nil {
			return tenantctx.Actor{}, ErrNoSession
		}
		t, err := m.st.Tenant(ctx, s.TenantID)
		if err != nil || t.Status != "active" {
			return tenantctx.Actor{}, ErrNoSession
		}
		pol, err := tenant.ParsePolicy(t.Policy, t.Kind == "platform")
		if err != nil {
			return tenantctx.Actor{}, err
		}
		roles, err := m.st.Roles(ctx, s.TenantID, s.UserID)
		if err != nil {
			return tenantctx.Actor{}, err
		}
		v = view{ID: s.ID, TenantID: s.TenantID, UserID: s.UserID, Roles: nonNil(roles), AMR: s.AMR, Operator: t.Kind == "platform", CreatedAt: s.CreatedAt, LastSeen: s.LastSeen, ExpiresAt: s.ExpiresAt, Idle: pol.IdleTimeout.D()}
		v.PolicyVersion = m.tenantVersion(ctx, s.TenantID)
		m.loadProfile(ctx, &v)
	} else {
		v, _ = m.refreshIfStale(ctx, v)
	}
	if !now.Before(v.ExpiresAt) {
		_ = m.expire(ctx, v, hash, ReasonExpired)
		return tenantctx.Actor{}, ErrNoSession
	}
	if now.Sub(v.LastSeen) > v.Idle {
		_ = m.expire(ctx, v, hash, ReasonIdle)
		return tenantctx.Actor{}, ErrNoSession
	}
	if m.revoked(ctx, v) {
		m.evictView(ctx, hash)
		return tenantctx.Actor{}, ErrNoSession
	}
	if now.Sub(v.LastSeen) >= time.Minute {
		if err := m.st.Touch(ctx, v.TenantID, v.ID); err == nil {
			v.LastSeen = now
		}
	}
	m.putView(ctx, hash, v)
	return v.actor(), nil
}

func (v view) actor() tenantctx.Actor {
	kind := tenantctx.KindUser
	if v.Operator {
		kind = tenantctx.KindOperator
	}
	return tenantctx.Actor{Kind: kind, UserID: v.UserID, TenantID: v.TenantID, SessionID: v.ID, Roles: v.Roles, AMR: v.AMR, DisplayName: v.DisplayName, AvatarURL: v.AvatarURL}
}

// ByID resolves a live session by tenant and id without the cookie secret
// (gateway token refresh). Same liveness rules as Resolve, but the session is
// not touched and no view is cached.
func (m *Manager) ByID(ctx context.Context, tenantID, id string) (tenantctx.Actor, error) {
	if tenantID == "" || id == "" {
		return tenantctx.Actor{}, ErrNoSession
	}
	s, err := m.st.Get(ctx, tenantID, id)
	if err != nil || s.RevokedAt != nil {
		return tenantctx.Actor{}, ErrNoSession
	}
	t, err := m.st.Tenant(ctx, s.TenantID)
	if err != nil || t.Status != "active" {
		return tenantctx.Actor{}, ErrNoSession
	}
	pol, err := tenant.ParsePolicy(t.Policy, t.Kind == "platform")
	if err != nil {
		return tenantctx.Actor{}, err
	}
	roles, err := m.st.Roles(ctx, s.TenantID, s.UserID)
	if err != nil {
		return tenantctx.Actor{}, err
	}
	v := view{ID: s.ID, TenantID: s.TenantID, UserID: s.UserID, Roles: nonNil(roles), AMR: s.AMR, Operator: t.Kind == "platform", CreatedAt: s.CreatedAt, LastSeen: s.LastSeen, ExpiresAt: s.ExpiresAt, Idle: pol.IdleTimeout.D()}
	m.loadProfile(ctx, &v)
	now := m.now()
	if !now.Before(v.ExpiresAt) || now.Sub(v.LastSeen) > v.Idle || m.revoked(ctx, v) {
		return tenantctx.Actor{}, ErrNoSession
	}
	return v.actor(), nil
}

func (m *Manager) getView(ctx context.Context, hash string) (view, bool) {
	if m.cache == nil {
		return view{}, false
	}
	raw, ok, err := m.cache.KV().Get(ctx, cache.SessionKey(hash))
	if err != nil || !ok {
		return view{}, false
	}
	var v view
	if json.Unmarshal([]byte(raw), &v) != nil {
		return view{}, false
	}
	return v, true
}

func (m *Manager) evictView(ctx context.Context, hash string) {
	if m.cache != nil {
		_ = m.cache.KV().Del(ctx, cache.SessionKey(hash))
	}
}

// revoked checks the session, user and tenant marks (ts ≥ created_at).
func (m *Manager) revoked(ctx context.Context, v view) bool {
	if m.cache == nil {
		return false
	}
	if _, ok, _ := m.cache.RevokedAt(ctx, cache.RevokedSessionKey(v.ID)); ok {
		return true
	}
	for _, key := range []string{cache.RevokedUserKey(v.UserID), cache.RevokedTenantKey(v.TenantID)} {
		if at, ok, _ := m.cache.RevokedAt(ctx, key); ok && !at.Before(v.CreatedAt) {
			return true
		}
	}
	return false
}

func (m *Manager) expire(ctx context.Context, v view, hash, reason string) error {
	m.evictView(ctx, hash)
	return m.revokeOne(ctx, v.TenantID, v.ID, v.UserID, reason, tenantctx.Actor{Kind: tenantctx.KindSystem})
}

// Revoke ends one session (sign-out or the user's own list).
func (m *Manager) Revoke(ctx context.Context, tenantID, id, reason string) error {
	s, err := m.st.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	actor, _ := tenantctx.FromContext(ctx)
	if err := m.revokeOne(ctx, tenantID, id, s.UserID, reason, actor); err != nil {
		return err
	}
	m.evictView(ctx, string(s.SecretHash))
	return nil
}

func (m *Manager) revokeOne(ctx context.Context, tenantID, id, userID, reason string, actor tenantctx.Actor) error {
	now := m.now()
	if err := m.st.Revoke(ctx, tenantID, id, reason); err != nil {
		return err
	}
	if err := m.publish(ctx, store.Revocation{TS: now, Kind: "session", SubjectID: id, TenantID: tenantID, Reason: reason}); err != nil {
		return err
	}
	typ := audit.SessionRevoked
	if reason == ReasonSignout {
		typ = audit.Signout
	}
	m.emit(audit.Event{Type: typ, TenantID: tenantID, ActorKind: kindOrSystem(actor), ActorUserID: actor.UserID, SubjectKind: "session", SubjectID: id, Outcome: "ok", Reason: reason,
		Details: map[string]any{"user_id": userID}})
	return nil
}

// RevokeUser ends every session of a user except keepID ("" = all).
func (m *Manager) RevokeUser(ctx context.Context, tenantID, userID, reason, keepID string) error {
	// List the live sessions before marking them: the listing only returns
	// unrevoked rows, and the cached views of the others must be evicted.
	var sessions []store.Session
	if keepID != "" {
		var err error
		if sessions, err = m.st.ListUser(ctx, tenantID, userID); err != nil {
			return err
		}
	}
	if err := m.st.RevokeUser(ctx, tenantID, userID, reason, keepID); err != nil {
		return err
	}
	now := m.now()
	if keepID == "" {
		if err := m.publish(ctx, store.Revocation{TS: now, Kind: "user", SubjectID: userID, TenantID: tenantID, Reason: reason}); err != nil {
			return err
		}
	} else {
		// Keeping one session: publish per-session entries for the others.
		for _, s := range sessions {
			if s.ID != keepID {
				if err := m.publish(ctx, store.Revocation{TS: now, Kind: "session", SubjectID: s.ID, TenantID: tenantID, Reason: reason}); err != nil {
					return err
				}
				m.evictView(ctx, string(s.SecretHash))
			}
		}
	}
	actor, _ := tenantctx.FromContext(ctx)
	m.emit(audit.Event{Type: audit.SessionRevoked, TenantID: tenantID, ActorKind: kindOrSystem(actor), ActorUserID: actor.UserID, SubjectKind: "user", SubjectID: userID, Outcome: "ok", Reason: reason})
	return nil
}

// RevokeTenant ends every session in a tenant (suspension).
func (m *Manager) RevokeTenant(ctx context.Context, tenantID, reason string) error {
	if err := m.st.RevokeTenant(ctx, tenantID, reason); err != nil {
		return err
	}
	if err := m.publish(ctx, store.Revocation{TS: m.now(), Kind: "tenant", SubjectID: tenantID, TenantID: tenantID, Reason: reason}); err != nil {
		return err
	}
	actor, _ := tenantctx.FromContext(ctx)
	m.emit(audit.Event{Type: audit.SessionRevoked, TenantID: tenantID, ActorKind: kindOrSystem(actor), ActorUserID: actor.UserID, SubjectKind: "tenant", SubjectID: tenantID, Outcome: "ok", Reason: reason})
	return nil
}

// publish writes the feed row and the cache mark, then fans out.
func (m *Manager) publish(ctx context.Context, r store.Revocation) error {
	if err := m.st.InsertRevocation(ctx, r); err != nil {
		return err
	}
	if m.cache == nil {
		return nil
	}
	var key string
	switch r.Kind {
	case "session":
		key = cache.RevokedSessionKey(r.SubjectID)
	case "user":
		key = cache.RevokedUserKey(r.SubjectID)
	case "tenant":
		key = cache.RevokedTenantKey(r.SubjectID)
	default:
		return fmt.Errorf("session: unknown revocation kind %q", r.Kind)
	}
	return m.cache.MarkRevoked(ctx, key, r.TS, RevocationRetention)
}

// Since returns feed entries after since (for auth.v1.Sessions/RevokedSince).
func (m *Manager) Since(ctx context.Context, since time.Time, limit int) ([]store.Revocation, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	return m.st.RevocationsSince(ctx, since, limit)
}

// View is a session as shown to its owner.
type View struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Current    bool      `json:"current"`
	UserAgent  string    `json:"user_agent"`
}

// ListMine lists the live sessions of a user.
func (m *Manager) ListMine(ctx context.Context, tenantID, userID, currentID string) ([]View, error) {
	sessions, err := m.st.ListUser(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	now := m.now()
	out := []View{}
	for _, s := range sessions {
		if s.RevokedAt != nil || !now.Before(s.ExpiresAt) {
			continue
		}
		out = append(out, View{ID: s.ID, CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeen, ExpiresAt: s.ExpiresAt, Current: s.ID == currentID, UserAgent: s.UserAgent})
	}
	return out, nil
}

func (m *Manager) emit(e audit.Event) {
	if m.audit != nil {
		_ = m.audit.Emit(e)
	}
}

func kindOrSystem(a tenantctx.Actor) string {
	if a.Kind == "" {
		return string(tenantctx.KindSystem)
	}
	return string(a.Kind)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
