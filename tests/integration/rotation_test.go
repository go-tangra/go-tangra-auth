//go:build integration

package integration

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestKeyRotation: SC-007 — three rotations under ~200 verifications/s with
// zero verification errors; the retired key stays published.
func TestKeyRotation(t *testing.T) {
	e := Start(t)
	e.Seed("acme", "alice@acme.test", pw, "")
	if code := e.SignIn("acme", "alice@acme.test", pw); code != 200 {
		t.Fatal(code)
	}
	mint := func() string {
		_, out := e.JSON(http.MethodPost, "/api/v1/session/token", nil)
		return out["access_token"].(string)
	}
	v := e.Verifier(nil)
	first := e.App.Ring.Keys()[0].KID
	var errs, total atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	tok := mint()
	var mu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(5 * time.Millisecond) // ≈200/s
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				mu.Lock()
				cur := tok
				mu.Unlock()
				total.Add(1)
				if _, err := v.Verify(context.Background(), cur); err != nil {
					errs.Add(1)
				}
			}
		}
	}()
	for i := 0; i < 3; i++ {
		time.Sleep(500 * time.Millisecond)
		if err := e.App.Ring.Rotate(context.Background()); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		tok = mint()
		mu.Unlock()
	}
	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()
	if errs.Load() != 0 || total.Load() < 300 {
		t.Fatalf("errors=%d total=%d", errs.Load(), total.Load())
	}
	found := false
	for _, k := range e.App.Ring.Keys() {
		if k.KID == first {
			found = true
		}
	}
	if !found {
		t.Fatal("rotated-out key must remain published until its tokens expire")
	}
}
