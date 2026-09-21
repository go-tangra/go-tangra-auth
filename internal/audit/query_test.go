package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/memstore"
	"github.com/go-freya/freya/services/auth/internal/store"
)

func TestQueryFiltersAndPaging(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	base := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
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
	for _, bad := range []Filter{{EventType: "made_up"}, {Cursor: "x"}, {From: base.Add(time.Hour), To: base}} {
		if _, err := Query(ctx, ms, "t1", bad); !errors.Is(err, ErrFilter) {
			t.Errorf("%+v accepted", bad)
		}
	}
}
