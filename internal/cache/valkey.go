package cache

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	valkey "github.com/valkey-io/valkey-go"
)

// ValkeyConfig connects to Valkey. TLS is required unless AllowPlaintext.
type ValkeyConfig struct {
	Addresses      []string
	Username       string
	Password       string
	AllowPlaintext bool
	CAPEM          []byte // optional private CA for the server certificate
}

type valkeyKV struct{ c valkey.Client }

// NewValkey returns a KV backed by Valkey (TLS 1.3 enforced when TLS is used).
func NewValkey(cfg ValkeyConfig) (KV, error) {
	if len(cfg.Addresses) == 0 {
		return nil, errors.New("cache: valkey addresses required")
	}
	opt := valkey.ClientOption{InitAddress: cfg.Addresses, Username: cfg.Username, Password: cfg.Password}
	if !cfg.AllowPlaintext {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		if len(cfg.CAPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CAPEM) {
				return nil, errors.New("cache: valkey ca is not valid PEM")
			}
			opt.TLSConfig.RootCAs = pool
		}
	}
	c, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("cache: %w", err)
	}
	return &valkeyKV{c: c}, nil
}

func (v *valkeyKV) Get(ctx context.Context, key string) (string, bool, error) {
	s, err := v.c.Do(ctx, v.c.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return s, true, nil
}

func (v *valkeyKV) GetDel(ctx context.Context, key string) (string, bool, error) {
	s, err := v.c.Do(ctx, v.c.B().Getdel().Key(key).Build()).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return s, true, nil
}

func (v *valkeyKV) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if ttl > 0 {
		return v.c.Do(ctx, v.c.B().Set().Key(key).Value(value).Px(ttl).Build()).Error()
	}
	return v.c.Do(ctx, v.c.B().Set().Key(key).Value(value).Build()).Error()
}

func (v *valkeyKV) Del(ctx context.Context, keys ...string) error {
	return v.c.Do(ctx, v.c.B().Del().Key(keys...).Build()).Error()
}

func (v *valkeyKV) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	n, err := v.c.Do(ctx, v.c.B().Incr().Key(key).Build()).AsInt64()
	if err != nil {
		return 0, err
	}
	if n == 1 && ttl > 0 {
		_ = v.c.Do(ctx, v.c.B().Pexpire().Key(key).Milliseconds(ttl.Milliseconds()).Build()).Error()
	}
	return n, nil
}

func (v *valkeyKV) Publish(ctx context.Context, channel, msg string) error {
	return v.c.Do(ctx, v.c.B().Publish().Channel(channel).Message(msg).Build()).Error()
}

func (v *valkeyKV) Subscribe(ctx context.Context, channel string, onMessage func(string)) error {
	return v.c.Receive(ctx, v.c.B().Subscribe().Channel(channel).Build(), func(m valkey.PubSubMessage) { onMessage(m.Message) })
}

func (v *valkeyKV) Close() { v.c.Close() }
