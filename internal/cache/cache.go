package cache

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// KV is the minimal key-value surface the service needs; implemented by Valkey
// and by an in-memory fake for tests.
type KV interface {
	Get(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	Publish(ctx context.Context, channel, msg string) error
	Subscribe(ctx context.Context, channel string, onMessage func(string)) error
	Close()
}

// Keys (data-model.md).
func SessionKey(sid string) string             { return "sess:" + sid }
func RevokedSessionKey(sid string) string      { return "rev:sid:" + sid }
func RevokedUserKey(uid string) string         { return "rev:user:" + uid }
func RevokedTenantKey(tid string) string       { return "rev:tenant:" + tid }
func LockKey(uid string) string                { return "lock:" + uid }
func RateKey(kind, subject string) string      { return "rl:" + kind + ":" + subject }
func DecisionKey(tid, uid, perm string) string { return "dec:" + tid + ":" + uid + ":" + perm }
func TenantVersionKey(tid string) string       { return "tenantver:" + tid }
func CodeKey(hash string) string               { return "code:" + hash }
func ChallengeKey(id string) string            { return "mfa:" + id }

// RevokedChannel fans revocations out to every instance.
const RevokedChannel = "auth:revoked"

// Cache wraps a KV with the service's operations.
type Cache struct{ kv KV }

// New wraps kv.
func New(kv KV) *Cache { return &Cache{kv: kv} }

// KV exposes the underlying store.
func (c *Cache) KV() KV { return c.kv }

// Close releases the client.
func (c *Cache) Close() { c.kv.Close() }

// MarkRevoked writes a revocation mark with ttl and publishes it.
func (c *Cache) MarkRevoked(ctx context.Context, key string, at time.Time, ttl time.Duration) error {
	if err := c.kv.Set(ctx, key, strconv.FormatInt(at.UnixNano(), 10), ttl); err != nil {
		return err
	}
	return c.kv.Publish(ctx, RevokedChannel, key+"|"+strconv.FormatInt(at.UnixNano(), 10))
}

// RevokedAt returns the revocation time for key, if any.
func (c *Cache) RevokedAt(ctx context.Context, key string) (time.Time, bool, error) {
	v, ok, err := c.kv.Get(ctx, key)
	if err != nil || !ok {
		return time.Time{}, false, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("cache: corrupt revocation mark: %w", err)
	}
	return time.Unix(0, n), true, nil
}

// Count increments a windowed counter and returns the new value.
func (c *Cache) Count(ctx context.Context, key string, window time.Duration) (int64, error) {
	return c.kv.Incr(ctx, key, window)
}

// Locked reports whether an account lockout is active.
func (c *Cache) Locked(ctx context.Context, uid string) (bool, error) {
	_, ok, err := c.kv.Get(ctx, LockKey(uid))
	return ok, err
}

// Lock sets an account lockout.
func (c *Cache) Lock(ctx context.Context, uid string, d time.Duration) error {
	return c.kv.Set(ctx, LockKey(uid), "1", d)
}

// Unlock clears a lockout.
func (c *Cache) Unlock(ctx context.Context, uid string) error { return c.kv.Del(ctx, LockKey(uid)) }

// TenantVersion returns the tenant's policy version counter.
func (c *Cache) TenantVersion(ctx context.Context, tid string) (int64, error) {
	v, ok, err := c.kv.Get(ctx, TenantVersionKey(tid))
	if err != nil || !ok {
		return 0, err
	}
	return strconv.ParseInt(v, 10, 64)
}

// BumpTenantVersion invalidates decision caches for a tenant.
func (c *Cache) BumpTenantVersion(ctx context.Context, tid string) (int64, error) {
	return c.kv.Incr(ctx, TenantVersionKey(tid), 0)
}

// ErrNotFound for typed lookups.
var ErrNotFound = errors.New("cache: not found")
