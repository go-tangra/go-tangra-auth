package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

func TestQueryFiltersAndPaging(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	// Within the default window (the legacy path lists the last 7 days too).
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Minute)
	alice, bob := "u-alice", "u-bob"
	for i := 0; i < 7; i++ {
		e := Event{Type: SigninOK, TenantID: "t1", ActorKind: "user", ActorUserID: alice, Outcome: "ok"}
		if i%2 == 1 {
			e = Event{Type: SigninFailed, TenantID: "t1", ActorKind: "user", ActorUserID: bob, Outcome: "refused", Reason: "wrong_password"}
		}
		r, _ := Row(e, base.Add(time.Duration(i)*time.Minute))
		_ = ms.InsertAuditRows(ctx, []store.AuditRow{r})
	}
	r, _ := Row(Event{Type: SigninOK, TenantID: "t2", ActorKind: "user", ActorUserID: alice, Outcome: "ok"}, base)
	_ = ms.InsertAuditRows(ctx, []store.AuditRow{r})

	page, err := Query(ctx, ms, "t1", Filter{Limit: 3})
	if err != nil || len(page.Items) != 3 || page.NextCursor == "" || !page.Items[0].TS.After(page.Items[1].TS) {
		t.Fatalf("%+v %v", page, err)
	}
	page2, err := Query(ctx, ms, "t1", Filter{Limit: 3, Cursor: page.NextCursor})
	if err != nil || len(page2.Items) != 3 || !page2.Items[0].TS.Before(page.Items[2].TS) {
		t.Fatalf("%+v %v", page2, err)
	}
	page3, _ := Query(ctx, ms, "t1", Filter{Limit: 3, Cursor: page2.NextCursor})
	if len(page3.Items) != 1 || page3.NextCursor != "" {
		t.Fatalf("%+v", page3)
	}
	if p, _ := Query(ctx, ms, "t1", Filter{UserID: bob}); len(p.Items) != 3 || p.Items[0].EventType != "signin_failed" {
		t.Fatalf("user filter %+v", p)
	}
	if p, _ := Query(ctx, ms, "t1", Filter{EventType: "signin_ok"}); len(p.Items) != 4 {
		t.Fatalf("type filter %+v", p)
	}
	if p, _ := Query(ctx, ms, "t1", Filter{From: base.Add(2 * time.Minute), To: base.Add(4 * time.Minute)}); len(p.Items) != 3 {
		t.Fatalf("time filter %+v", p)
	}
	// Tenant scoping comes from the caller, never from the filter.
	if p, _ := Query(ctx, ms, "t2", Filter{}); len(p.Items) != 1 {
		t.Fatalf("scope %+v", p)
	}
	for _, bad := range []Filter{{EventType: "made_up"}, {Cursor: "x"}, {Cursor: "1.x"}, {Cursor: "1.0"}, {From: base.Add(time.Hour), To: base}} {
		if _, err := Query(ctx, ms, "t1", bad); !errors.Is(err, ErrFilter) {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// TestSpanCap: an explicit window wider than store.MaxAuditSpan is ErrSpan
// naming from on both paths; exactly 90 days passes (security review F-2).
func TestSpanCap(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	now := time.Now()
	if store.MaxAuditSpan != 90*24*time.Hour {
		t.Fatalf("MaxAuditSpan %v", store.MaxAuditSpan)
	}
	day := 24 * time.Hour
	for _, f := range []Filter{{From: now.Add(-91 * day), To: now}, {From: now.Add(-91 * day)}, {From: time.Unix(0, 0)}} {
		var le *listquery.Error
		if _, err := List(ctx, ms, "t1", f, listquery.Request{}, now); !errors.As(err, &le) || le.Param != "from" {
			t.Fatalf("paged %+v: %v", f, err)
		}
		if _, err := Query(ctx, ms, "t1", f); !errors.As(err, &le) || le.Param != "from" {
			t.Fatalf("legacy %+v: %v", f, err)
		}
	}
	for _, f := range []Filter{{From: now.Add(-90 * day), To: now}, {From: now.Add(-90 * day).Add(time.Second)}, {}, {To: now.Add(-365 * day)}} {
		if _, err := List(ctx, ms, "t1", f, listquery.Request{}, now); err != nil {
			t.Fatalf("paged %+v: %v", f, err)
		}
		if _, err := Query(ctx, ms, "t1", f); err != nil {
			t.Fatalf("legacy %+v: %v", f, err)
		}
	}
}

// Events sharing a timestamp page exactly once (id tie-breaker) on both paths;
// List applies the default window and counts within it.
func TestListWindowAndTies(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 5; i++ {
		r, _ := Row(Event{Type: SigninOK, TenantID: "t1", ActorKind: "user", Outcome: "ok"}, now.Add(-time.Hour))
		_ = ms.InsertAuditRows(ctx, []store.AuditRow{r})
	}
	old, _ := Row(Event{Type: SigninOK, TenantID: "t1", ActorKind: "user", Outcome: "ok"}, now.Add(-8*24*time.Hour))
	_ = ms.InsertAuditRows(ctx, []store.AuditRow{old})
	seen := map[string]bool{}
	for p := 1; p <= 3; p++ {
		pg, err := List(ctx, ms, "t1", Filter{}, listquery.Request{Page: p, PageSize: 2, Sort: "ts", Order: listquery.Desc}, now)
		if err != nil || pg.Total != 5 {
			t.Fatalf("page %d: %+v %v", p, pg, err)
		}
		for _, it := range pg.Items {
			if seen[it.ID] {
				t.Fatalf("%s repeated", it.ID)
			}
			seen[it.ID] = true
		}
	}
	if len(seen) != 5 {
		t.Fatalf("reached %d of 5", len(seen))
	}
	if pg, _ := List(ctx, ms, "t1", Filter{From: now.Add(-10 * 24 * time.Hour)}, listquery.Request{Page: 1, PageSize: 50, Sort: "ts", Order: listquery.Desc}, now); pg.Total != 6 {
		t.Fatalf("explicit window %d", pg.Total)
	}
	if _, err := List(ctx, ms, "t1", Filter{EventType: "made_up"}, listquery.Request{Page: 1, PageSize: 5, Sort: "ts", Order: listquery.Desc}, now); !errors.Is(err, ErrFilter) {
		t.Fatal("unknown event type accepted")
	}
	// Legacy: two per page, the cursor carries the id.
	legacy, cur := map[string]bool{}, ""
	for i := 0; i < 5; i++ {
		pg, err := Query(ctx, ms, "t1", Filter{Limit: 2, Cursor: cur})
		if err != nil || pg.Total != 5 {
			t.Fatalf("%+v %v", pg, err)
		}
		for _, it := range pg.Items {
			legacy[it.ID] = true
		}
		if cur = pg.NextCursor; cur == "" {
			break
		}
	}
	if len(legacy) != 5 {
		t.Fatalf("legacy reached %d of 5", len(legacy))
	}
}
