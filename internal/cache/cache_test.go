package cache

import (
	"context"
	"testing"
	"time"
)

func TestMemoryKVAndCacheOps(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	now := time.Now()
	m.now = func() time.Time { return now }
	c := New(m)
	if _, ok, _ := c.KV().Get(ctx, "x"); ok {
		t.Fatal("empty")
	}
	_ = c.KV().Set(ctx, SessionKey("s1"), "u1", time.Minute)
	if v, ok, _ := c.KV().Get(ctx, SessionKey("s1")); !ok || v != "u1" {
		t.Fatal("set/get")
	}
	now = now.Add(2 * time.Minute)
	if _, ok, _ := c.KV().Get(ctx, SessionKey("s1")); ok {
		t.Fatal("ttl must expire")
	}
	// Revocation marks + pub/sub fan-out.
	got := make(chan string, 1)
	subCtx, cancel := context.WithCancel(ctx)
	go func() { _ = m.Subscribe(subCtx, RevokedChannel, func(s string) { got <- s }) }()
	time.Sleep(10 * time.Millisecond)
	at := now
	if err := c.MarkRevoked(ctx, RevokedSessionKey("s1"), at, time.Hour); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-got:
		if msg == "" {
			t.Fatal("empty message")
		}
	case <-time.After(time.Second):
		t.Fatal("no fan-out")
	}
	cancel()
	when, ok, err := c.RevokedAt(ctx, RevokedSessionKey("s1"))
	if err != nil || !ok || !when.Equal(at) {
		t.Fatalf("%v %v %v", when, ok, err)
	}
	if _, ok, _ := c.RevokedAt(ctx, RevokedSessionKey("nope")); ok {
		t.Fatal("unknown mark")
	}
	_ = c.KV().Set(ctx, RevokedUserKey("bad"), "x", 0)
	if _, _, err := c.RevokedAt(ctx, RevokedUserKey("bad")); err == nil {
		t.Fatal("corrupt mark must error")
	}
	// Counters with window, lockouts, tenant version.
	for i := 1; i <= 3; i++ {
		if n, _ := c.Count(ctx, RateKey("signin", "ip1"), time.Minute); n != int64(i) {
			t.Fatalf("count %d", n)
		}
	}
	now = now.Add(2 * time.Minute)
	if n, _ := c.Count(ctx, RateKey("signin", "ip1"), time.Minute); n != 1 {
		t.Fatalf("window reset: %d", n)
	}
	if l, _ := c.Locked(ctx, "u1"); l {
		t.Fatal("not locked")
	}
	_ = c.Lock(ctx, "u1", time.Minute)
	if l, _ := c.Locked(ctx, "u1"); !l {
		t.Fatal("locked")
	}
	_ = c.Unlock(ctx, "u1")
	if l, _ := c.Locked(ctx, "u1"); l {
		t.Fatal("unlocked")
	}
	if v, _ := c.TenantVersion(ctx, "t1"); v != 0 {
		t.Fatal("version 0")
	}
	if v, _ := c.BumpTenantVersion(ctx, "t1"); v != 1 {
		t.Fatal("bump")
	}
	if v, _ := c.TenantVersion(ctx, "t1"); v != 1 {
		t.Fatal("version 1")
	}
	_ = c.KV().Del(ctx, TenantVersionKey("t1"))
	if DecisionKey("t", "u", "p") != "dec:t:u:p" || CodeKey("h") != "code:h" || ChallengeKey("c") != "mfa:c" || RevokedTenantKey("t") != "rev:tenant:t" {
		t.Fatal("keys")
	}
	c.Close()
	if _, err := NewValkey(ValkeyConfig{}); err == nil {
		t.Fatal("addresses required")
	}
}

func TestValkeyConfigErrors(t *testing.T) {
	if _, err := NewValkey(ValkeyConfig{Addresses: []string{"127.0.0.1:1"}, CAPEM: []byte("not pem")}); err == nil {
		t.Fatal("invalid CA accepted")
	}
	// A syntactically valid CA is accepted; the dial to a closed port fails.
	pem := []byte("-----BEGIN CERTIFICATE-----\nMIIBHzCBxaADAgECAgEBMAoGCCqGSM49BAMCMA0xCzAJBgNVBAMTAmNhMB4XDTI2\nMDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowDTELMAkGA1UEAxMCY2EwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAAT0jvjl9m3HwxuI6mJ8fO3w3bAbiVpSmyDl9Xm8\n6Oo1ZQt0Yd1pM0WcQm3n5m1uQ1P5m8Q5c8Kq7dY3m9k8jH3oxDAKBggqhkjOPQQD\nAgNJADBGAiEAq7l3s0VbyK9zB2jvN7nR6QvUqQ3gk1nZK9qXAO3E1GkCIQC7Hrvq\n8wG2QWlQm5kQ1cP2JzR0cV9vN1cQ8Jm7k0K2Yg==\n-----END CERTIFICATE-----\n")
	if _, err := NewValkey(ValkeyConfig{Addresses: []string{"127.0.0.1:1"}, CAPEM: pem}); err == nil {
		t.Fatal("closed port must fail")
	}
	if _, err := NewValkey(ValkeyConfig{Addresses: []string{"127.0.0.1:1"}, AllowPlaintext: true}); err == nil {
		t.Fatal("closed port must fail (plaintext)")
	}
}
