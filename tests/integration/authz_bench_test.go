//go:build integration

package integration

import (
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/authz"
)

// BenchmarkCheck: SC-005 — p95 decision latency under 1,000 concurrent
// callers below 20 ms (cached path after warm-up). Run through
// scripts/authz-gate.sh, which parses the reported p95.
func BenchmarkCheck(b *testing.B) {
	t := &testing.T{}
	e := Start(t)
	tid, owner := e.Seed("acme", "owner@acme.test", pw, "")
	roles := e.SeedRoles(tid)
	e.Bind(tid, owner, roles, "owner")
	_, _ = e.App.Registry.Register(svcCtx(), tid, "svc", []authz.Permission{{Resource: "invoices", Action: "read"}})
	if e.SignIn("acme", "owner@acme.test", pw) != 200 {
		b.Fatal("sign-in")
	}
	_, role := e.JSON(http.MethodPost, "/api/v1/admin/roles", map[string]any{"slug": "reviewer", "display_name": "Reviewer", "permissions": []string{"invoices:read"}})
	_, carol := e.Seed("acme", "carol@acme.test", pw, "")
	e.JSON(http.MethodPut, "/api/v1/admin/users/"+carol+"/roles", map[string]any{"role_ids": []string{role["id"].(string)}})
	read := authz.PermissionRef{Resource: "invoices", Action: "read"}
	ctx := svcCtx()
	const workers = 1000
	var mu sync.Mutex
	var lat []time.Duration
	b.ResetTimer()
	var wg sync.WaitGroup
	per := b.N/workers + 1
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				start := time.Now()
				if _, err := e.App.Decider.Decide(ctx, tid, carol, read); err != nil {
					b.Error(err)
					return
				}
				d := time.Since(start)
				mu.Lock()
				lat = append(lat, d)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	b.StopTimer()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p95 := lat[len(lat)*95/100]
	b.ReportMetric(float64(p95.Microseconds())/1000, "p95_ms")
}
