package password

import (
	"context"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/store"
)

// TestRecoveryImportedIsUnknown (feature 016, SR-006/SC-002): asking to reset
// the password of an imported (never activated) account gets exactly what an
// unknown address gets — the same acknowledgement, the same timing pad, no
// outbox row, no recovery request, and an unknown_account audit event.
func TestRecoveryImportedIsUnknown(t *testing.T) {
	ms, sm, ob := setup(t)
	ctx := context.Background()
	h, _ := Hash("old-password-1")
	ms.AddUser(store.User{ID: "u-imp", TenantID: tid, Email: "imported@x.test", Status: "imported"})
	ms.AddUser(store.User{ID: "u-imp-hash", TenantID: tid, Email: "imported-hash@x.test", Status: "imported", PasswordHash: &h})
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	rec := NewRecovery(ms, ob, sm, aw, "https://auth.example.org")
	var pads []time.Time
	rec.SetPad(func(start time.Time) { pads = append(pads, start) })

	// The acknowledgement is always nil; the pad must run exactly once.
	request := func(addr string) (int, error) {
		t.Helper()
		pads = nil
		err := rec.Request(ctx, "acme", addr, "ip")
		return len(pads), err
	}
	if n, err := request("ghost@x.test"); err != nil || n != 1 {
		t.Fatalf("baseline unknown: err=%v pads=%d", err, n)
	}
	for _, addr := range []string{"imported@x.test", " Imported-Hash@X.test "} {
		if n, err := request(addr); err != nil || n != 1 {
			t.Fatalf("%q: err=%v pads=%d, want the unknown-address ack", addr, err, n)
		}
		if pads[0].IsZero() {
			t.Fatalf("%q: pad must measure from the request start", addr)
		}
	}
	if len(ms.Outbox) != 0 || len(ms.Recoveries) != 0 {
		t.Fatalf("imported address queued mail or a request: outbox=%d recoveries=%d", len(ms.Outbox), len(ms.Recoveries))
	}
	aw.Flush()
	var refused int
	for _, r := range ms.AuditRows {
		if r.EventType != string(audit.RecoveryRequested) {
			continue
		}
		if r.Outcome != "refused" || r.Reason != "unknown_account" || r.ActorUserID != nil {
			t.Fatalf("recovery audit must look like an unknown account: %+v", r)
		}
		refused++
	}
	if refused != 3 {
		t.Fatalf("want 3 unknown_account events, got %d", refused)
	}
}
