// Package authclient verifies access tokens issued by the auth service
// offline: published keys, EdDSA signatures, issuer/time checks and the
// revocation feed, failing closed when the feed is stale.
package authclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"
)

// KeySource fetches the current verification keys (JWKS over HTTPS or
// auth.v1.Keys/List over the service channel).
type KeySource interface {
	Keys(ctx context.Context) (map[string]ed25519.PublicKey, error)
}

// Revocation is one feed entry.
type Revocation struct {
	TS        time.Time
	Kind      string // session | user | tenant
	SubjectID string
	TenantID  string
	Reason    string
}

// RevocationSource pages the feed from a cursor ("" = retention window).
type RevocationSource interface {
	Since(ctx context.Context, cursor string) (entries []Revocation, next string, err error)
}

// Config tunes the verifier.
type Config struct {
	Issuer         string
	Audience       string        // optional expected aud
	TenantID       string        // optional: only tokens of this tenant
	Skew           time.Duration // ≤ 60s
	KeyRefresh     time.Duration // default 5m
	UnknownKidCap  time.Duration // min gap between unknown-kid refreshes; default 1m
	RevocationPoll time.Duration // default 5s
	MaxStale       time.Duration // fail closed after; default 60m
	Retention      time.Duration // feed window kept in memory; default 60m
}

// Identity is a verified end user.
type Identity struct {
	UserID, TenantID, SessionID string
	Roles, AMR                  []string
	Audience                    string
	IssuedAt, ExpiresAt         time.Time
	JTI                         string
}

// Errors.
var (
	ErrUnauthenticated = errors.New("authclient: unauthenticated")
	ErrRevoked         = errors.New("authclient: token revoked")
	ErrStale           = errors.New("authclient: revocation feed stale; failing closed")
	ErrWrongTenant     = errors.New("authclient: token belongs to another tenant")
)

// Verifier verifies tokens with cached keys and the revocation feed.
type Verifier struct {
	cfg  Config
	keys KeySource
	revs RevocationSource
	now  func() time.Time

	mu          sync.RWMutex
	keySet      map[string]ed25519.PublicKey
	keysAt      time.Time
	lastUnknown time.Time
	entries     []Revocation
	cursor      string
	revSyncedAt time.Time
	revSynced   bool
}

// New builds a verifier; revs may be nil (no revocation checks — only for
// callers that accept a full token lifetime of latency).
func New(cfg Config, keys KeySource, revs RevocationSource) *Verifier {
	if cfg.Skew <= 0 || cfg.Skew > 60*time.Second {
		cfg.Skew = 60 * time.Second
	}
	if cfg.KeyRefresh <= 0 {
		cfg.KeyRefresh = 5 * time.Minute
	}
	if cfg.UnknownKidCap <= 0 {
		cfg.UnknownKidCap = time.Minute
	}
	if cfg.RevocationPoll <= 0 {
		cfg.RevocationPoll = 5 * time.Second
	}
	if cfg.MaxStale <= 0 {
		cfg.MaxStale = 60 * time.Minute
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 60 * time.Minute
	}
	return &Verifier{cfg: cfg, keys: keys, revs: revs, now: time.Now, keySet: map[string]ed25519.PublicKey{}}
}

// RefreshKeys fetches the key set now.
func (v *Verifier) RefreshKeys(ctx context.Context) error {
	set, err := v.keys.Keys(ctx)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.keySet, v.keysAt = set, v.now()
	v.mu.Unlock()
	return nil
}

// SyncRevocations pulls the feed once. The first sync loads the whole
// retention window; later syncs continue from the cursor.
func (v *Verifier) SyncRevocations(ctx context.Context) error {
	if v.revs == nil {
		return nil
	}
	v.mu.RLock()
	cursor := v.cursor
	v.mu.RUnlock()
	for i := 0; i < 100; i++ {
		entries, next, err := v.revs.Since(ctx, cursor)
		if err != nil {
			return err
		}
		v.mu.Lock()
		v.entries = append(v.entries, entries...)
		v.cursor = next
		v.forgetExpired()
		v.mu.Unlock()
		if next == cursor || len(entries) == 0 {
			break
		}
		cursor = next
	}
	v.mu.Lock()
	v.revSyncedAt, v.revSynced = v.now(), true
	v.mu.Unlock()
	return nil
}

func (v *Verifier) forgetExpired() {
	cut := v.now().Add(-v.cfg.Retention)
	kept := v.entries[:0]
	for _, e := range v.entries {
		if e.TS.After(cut) {
			kept = append(kept, e)
		}
	}
	v.entries = kept
}

// Start runs key refresh and feed polling until ctx ends. It returns after
// the first attempt of each so callers can fail fast on misconfiguration.
func (v *Verifier) Start(ctx context.Context, onError func(error)) error {
	if err := v.RefreshKeys(ctx); err != nil {
		return err
	}
	if err := v.SyncRevocations(ctx); err != nil {
		return err
	}
	go v.loop(ctx, v.cfg.KeyRefresh, func() error { return v.RefreshKeys(ctx) }, onError)
	if v.revs != nil {
		go v.loop(ctx, v.cfg.RevocationPoll, func() error { return v.SyncRevocations(ctx) }, onError)
	}
	return nil
}

func (v *Verifier) loop(ctx context.Context, every time.Duration, fn func() error, onError func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := fn(); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

func (v *Verifier) lookup(kid string) (ed25519.PublicKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	k, ok := v.keySet[kid]
	return k, ok
}

// Verify checks a bearer token and returns the identity it proves.
func (v *Verifier) Verify(ctx context.Context, token string) (Identity, error) {
	c, err := VerifyToken(token, v.cfg.Issuer, v.cfg.Skew, MaxTokenLifetime, v.now, v.lookup)
	var unknown *UnknownKeyError
	if errors.As(err, &unknown) {
		// Rotation may have happened: refresh at most once per UnknownKidCap.
		v.mu.Lock()
		allowed := v.now().Sub(v.lastUnknown) >= v.cfg.UnknownKidCap
		if allowed {
			v.lastUnknown = v.now()
		}
		v.mu.Unlock()
		if allowed {
			if rerr := v.RefreshKeys(ctx); rerr == nil {
				c, err = VerifyToken(token, v.cfg.Issuer, v.cfg.Skew, MaxTokenLifetime, v.now, v.lookup)
			}
		}
	}
	if err != nil {
		return Identity{}, errors.Join(ErrUnauthenticated, err)
	}
	if v.cfg.Audience != "" && !containsAud(c.Audience, v.cfg.Audience) {
		return Identity{}, errors.Join(ErrUnauthenticated, errors.New("audience mismatch"))
	}
	if v.cfg.TenantID != "" && c.TenantID != v.cfg.TenantID {
		return Identity{}, ErrWrongTenant
	}
	if v.revs != nil {
		v.mu.RLock()
		synced, at := v.revSynced, v.revSyncedAt
		v.mu.RUnlock()
		if !synced || v.now().Sub(at) > v.cfg.MaxStale {
			return Identity{}, ErrStale
		}
		if v.revoked(c) {
			return Identity{}, ErrRevoked
		}
	}
	id := Identity{UserID: c.Subject, TenantID: c.TenantID, SessionID: c.SessionID, Roles: c.Roles, AMR: c.AMR, IssuedAt: c.IssuedAt.Time, ExpiresAt: c.ExpiresAt.Time, JTI: c.ID}
	if len(c.Audience) > 0 {
		id.Audience = c.Audience[0]
	}
	return id, nil
}

// revoked applies the contract rule: an entry for the session, user or
// tenant with ts ≥ iat (second granularity) invalidates the token.
func (v *Verifier) revoked(c Claims) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	iat := c.IssuedAt.Time.Unix()
	for _, e := range v.entries {
		if e.TS.Unix() < iat {
			continue
		}
		switch e.Kind {
		case "session":
			if e.SubjectID == c.SessionID {
				return true
			}
		case "user":
			if e.SubjectID == c.Subject && (e.TenantID == "" || e.TenantID == c.TenantID) {
				return true
			}
		case "tenant":
			if e.SubjectID == c.TenantID {
				return true
			}
		}
	}
	return false
}

func containsAud(aud []string, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}

// StaticKeys is a KeySource for tests and pinned deployments.
type StaticKeys map[string]ed25519.PublicKey

func (s StaticKeys) Keys(context.Context) (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out, nil
}

// SetClock overrides the verifier's clock (integration tests simulate expiry).
func SetClock(v *Verifier, now func() time.Time) {
	if now != nil {
		v.now = now
	}
}
