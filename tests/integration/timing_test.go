//go:build integration

package integration

import (
	"net/http"
	"sort"
	"testing"
	"time"
)

// TestEnumerationTiming: SC-006 — response time for an existing account with
// a wrong password and for a non-existing account differ by < 10 % (medians
// over 100 samples each, interleaved to cancel drift).
func TestEnumerationTiming(t *testing.T) {
	e := Start(t)
	e.Seed("acme", "alice@acme.test", pw, `{"lockout_threshold":20}`)
	var existing, missing []time.Duration
	for i := 0; i < 100; i++ {
		start := time.Now()
		e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "alice@acme.test", "password": "wrong-" + string(rune('a'+i%26))})
		existing = append(existing, time.Since(start))
		start = time.Now()
		e.JSON(http.MethodPost, "/api/v1/signin", map[string]string{"tenant": "acme", "email": "ghost" + string(rune('a'+i%26)) + "@acme.test", "password": pw})
		missing = append(missing, time.Since(start))
		if i%10 == 9 {
			time.Sleep(50 * time.Millisecond) // stay under the per-origin limit window
		}
	}
	med := func(d []time.Duration) time.Duration {
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		return d[len(d)/2]
	}
	a, b := med(existing), med(missing)
	spread := float64(a-b) / float64(a)
	if spread < 0 {
		spread = -spread
	}
	if spread >= 0.10 {
		t.Fatalf("timing spread %.1f%% (existing %v, missing %v)", spread*100, a, b)
	}
}
