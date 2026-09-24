package token

import (
	"context"
	stdcrypto "crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// KeyStore persists signing keys (database-backed or in-memory for tests).
type KeyStore interface {
	List(ctx context.Context) ([]store.SigningKey, error)
	Insert(ctx context.Context, k store.SigningKey) error
	SetState(ctx context.Context, kid, state string, at time.Time) error
	Remove(ctx context.Context, kid string) error
}

// Config drives rotation timing.
type Config struct {
	AccessLifetime   time.Duration // ≤ 15m
	RotationInterval time.Duration
	RetiringPeriod   time.Duration
	ClockSkew        time.Duration
}

type ringKey struct {
	store.SigningKey
	priv stdcrypto.Signer // nil once retired; Ed25519 today, HSM-backed tomorrow
}

// Ring holds the unsealed signing keys in memory and drives rotation:
// active → retiring (after RotationInterval) → retired (after RetiringPeriod)
// → removed once every token it could have signed has expired.
type Ring struct {
	ks   KeyStore
	env  *crypto.Envelope
	cfg  Config
	mu   sync.RWMutex
	keys map[string]*ringKey
	now  func() time.Time
}

// NewRing wires the ring; call Load before use.
func NewRing(ks KeyStore, env *crypto.Envelope, cfg Config) *Ring {
	if cfg.AccessLifetime <= 0 || cfg.AccessLifetime > 15*time.Minute {
		cfg.AccessLifetime = 15 * time.Minute
	}
	if cfg.RotationInterval <= 0 {
		cfg.RotationInterval = 24 * time.Hour
	}
	if cfg.RetiringPeriod <= 0 {
		cfg.RetiringPeriod = 30 * time.Minute
	}
	if cfg.ClockSkew <= 0 || cfg.ClockSkew > 60*time.Second {
		cfg.ClockSkew = 60 * time.Second
	}
	return &Ring{ks: ks, env: env, cfg: cfg, keys: map[string]*ringKey{}, now: time.Now}
}

// Load reads every key, unseals active/retiring ones and creates the first
// active key when none exists.
func (r *Ring) Load(ctx context.Context) error {
	keys, err := r.ks.List(ctx)
	if err != nil {
		return err
	}
	fresh := map[string]*ringKey{}
	active := false
	for _, k := range keys {
		rk := &ringKey{SigningKey: k}
		if k.State != StateRetired {
			if rk.priv, err = OpenKey(r.env, k); err != nil {
				return err
			}
		}
		if k.State == StateActive {
			active = true
		}
		fresh[k.KID] = rk
	}
	r.mu.Lock()
	r.keys = fresh
	r.mu.Unlock()
	if !active {
		return r.Rotate(ctx)
	}
	return nil
}

// Rotate creates a new active key and moves the current active one to retiring.
func (r *Ring) Rotate(ctx context.Context) error {
	now := r.now()
	k, err := GenerateKey(r.env, now)
	if err != nil {
		return err
	}
	priv, _ := OpenKey(r.env, k)
	r.mu.Lock()
	defer r.mu.Unlock()
	// The store allows one active key at a time: retire the current one before
	// inserting its successor, and put it back if the insert fails.
	var retired []*ringKey
	for _, old := range r.keys {
		if old.State == StateActive {
			if err := r.ks.SetState(ctx, old.KID, StateRetiring, now); err != nil {
				return err
			}
			old.State = StateRetiring
			t := now
			old.RetiringAt = &t
			retired = append(retired, old)
		}
	}
	if err := r.ks.Insert(ctx, k); err != nil {
		for _, old := range retired {
			if r.ks.SetState(ctx, old.KID, StateActive, now) == nil {
				old.State, old.RetiringAt = StateActive, nil
			}
		}
		return err
	}
	r.keys[k.KID] = &ringKey{SigningKey: k, priv: priv}
	return nil
}

// Sweep advances retiring keys to retired and forgets retired keys whose
// last possible token has expired. It also rotates when the active key is
// older than RotationInterval.
func (r *Ring) Sweep(ctx context.Context) error {
	now := r.now()
	r.mu.Lock()
	var rotate bool
	keep := map[string]*ringKey{}
	for kid, k := range r.keys {
		switch k.State {
		case StateActive:
			if now.Sub(k.CreatedAt) >= r.cfg.RotationInterval {
				rotate = true
			}
		case StateRetiring:
			if k.RetiringAt != nil && now.Sub(*k.RetiringAt) >= r.cfg.RetiringPeriod {
				if err := r.ks.SetState(ctx, kid, StateRetired, now); err != nil {
					r.mu.Unlock()
					return err
				}
				k.State, k.priv = StateRetired, nil
				t := now
				k.RetiredAt = &t
			}
		case StateRetired:
			// Only active keys sign, so nothing was signed after retiring
			// began; keep the key for the full token lifetime plus skew.
			if k.RetiredAt != nil && now.Sub(*k.RetiredAt) >= r.cfg.AccessLifetime+r.cfg.ClockSkew {
				if err := r.ks.Remove(ctx, kid); err != nil {
					r.mu.Unlock()
					return err
				}
				continue
			}
		}
		keep[kid] = k
	}
	r.keys = keep
	r.mu.Unlock()
	if rotate {
		return r.Rotate(ctx)
	}
	return nil
}

// Run sweeps every interval until ctx ends.
func (r *Ring) Run(ctx context.Context, every time.Duration, onError func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Sweep(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// ErrNoActiveKey is returned when issuing without a loaded ring.
var ErrNoActiveKey = errors.New("token: no active signing key")

func (r *Ring) active() (*ringKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var best *ringKey
	for _, k := range r.keys {
		if k.State == StateActive && (best == nil || k.CreatedAt.After(best.CreatedAt)) {
			best = k
		}
	}
	if best == nil {
		return nil, ErrNoActiveKey
	}
	return best, nil
}

// PublicKey returns the verification key for kid in any published state.
func (r *Ring) PublicKey(kid string) (ed25519.PublicKey, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.keys[kid]
	if !ok {
		return nil, false
	}
	return ed25519.PublicKey(k.PublicKey), true
}

// JWKS renders every key still needed for verification.
func (r *Ring) JWKS() authclient.JWKS {
	r.mu.RLock()
	defer r.mu.RUnlock()
	set := authclient.JWKS{Keys: []authclient.JWK{}}
	for _, k := range r.keys {
		set.Keys = append(set.Keys, authclient.NewJWK(k.KID, ed25519.PublicKey(k.PublicKey), k.State))
	}
	return set
}

// JWKSJSON is JWKS encoded (deterministic order by kid).
func (r *Ring) JWKSJSON() []byte {
	set := r.JWKS()
	sort.Slice(set.Keys, func(i, j int) bool { return set.Keys[i].Kid < set.Keys[j].Kid })
	b, _ := json.Marshal(set)
	return b
}

// Keys lists the ring's public metadata (for auth.v1.Keys/List).
func (r *Ring) Keys() []store.SigningKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]store.SigningKey, 0, len(r.keys))
	for _, k := range r.keys {
		out = append(out, k.SigningKey)
	}
	return out
}

// MemKeys is an in-memory KeyStore for tests and single-process development.
type MemKeys struct {
	mu   sync.Mutex
	keys map[string]store.SigningKey
}

func NewMemKeys() *MemKeys { return &MemKeys{keys: map[string]store.SigningKey{}} }

func (m *MemKeys) List(context.Context) ([]store.SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.SigningKey, 0, len(m.keys))
	for _, k := range m.keys {
		out = append(out, k)
	}
	return out, nil
}
func (m *MemKeys) Insert(_ context.Context, k store.SigningKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[k.KID] = k
	return nil
}
func (m *MemKeys) SetState(_ context.Context, kid, state string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[kid]
	if !ok {
		return store.ErrNotFound
	}
	k.State = state
	switch state {
	case StateRetiring:
		k.RetiringAt = &at
	case StateRetired:
		k.RetiredAt = &at
	}
	m.keys[kid] = k
	return nil
}
func (m *MemKeys) Remove(_ context.Context, kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[string]store.SigningKey{}
	for id, k := range m.keys {
		if id != kid {
			keep[id] = k
		}
	}
	m.keys = keep
	return nil
}
func (m *MemKeys) Len() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.keys) }
