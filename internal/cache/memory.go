package cache

import (
	"context"
	"sync"
	"time"
)

// Memory is an in-memory KV for tests and single-process development.
type Memory struct {
	mu   sync.Mutex
	data map[string]entry
	subs map[string][]func(string)
	now  func() time.Time
}

type entry struct {
	v   string
	exp time.Time
}

// NewMemory returns an empty in-memory KV.
func NewMemory() *Memory {
	return &Memory{data: map[string]entry{}, subs: map[string][]func(string){}, now: time.Now}
}

func (m *Memory) live(k string) (entry, bool) {
	e, ok := m.data[k]
	if !ok {
		return entry{}, false
	}
	if !e.exp.IsZero() && !m.now().Before(e.exp) {
		delete(m.data, k)
		return entry{}, false
	}
	return e, true
}

func (m *Memory) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.live(key)
	return e.v, ok, nil
}

func (m *Memory) GetDel(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.live(key)
	delete(m.data, key)
	return e.v, ok, nil
}

func (m *Memory) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := entry{v: value}
	if ttl > 0 {
		e.exp = m.now().Add(ttl)
	}
	m.data[key] = e
	return nil
}

func (m *Memory) Del(_ context.Context, keys ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		delete(m.data, k)
	}
	return nil
}

func (m *Memory) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.live(key)
	var n int64
	if ok {
		for _, ch := range e.v {
			n = n*10 + int64(ch-'0')
		}
	}
	n++
	ne := entry{v: itoa(n), exp: e.exp}
	if !ok && ttl > 0 {
		ne.exp = m.now().Add(ttl)
	}
	m.data[key] = ne
	return n, nil
}

func (m *Memory) Publish(_ context.Context, channel, msg string) error {
	m.mu.Lock()
	subs := append([]func(string){}, m.subs[channel]...)
	m.mu.Unlock()
	for _, s := range subs {
		s(msg)
	}
	return nil
}

func (m *Memory) Subscribe(ctx context.Context, channel string, onMessage func(string)) error {
	m.mu.Lock()
	m.subs[channel] = append(m.subs[channel], onMessage)
	m.mu.Unlock()
	<-ctx.Done()
	return nil
}

func (m *Memory) Close() {}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
