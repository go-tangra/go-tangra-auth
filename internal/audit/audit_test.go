package audit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/store"
)

type fakeIns struct {
	mu   sync.Mutex
	rows []store.AuditRow
	fail bool
}

func (f *fakeIns) InsertAuditRows(_ context.Context, rows []store.AuditRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("db down")
	}
	f.rows = append(f.rows, rows...)
	return nil
}
func (f *fakeIns) n() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.rows) }

// Feature 004: group and profile events are known; PII detail keys are redacted
// so a careless caller can never persist a phone number or a name.
func TestGroupAndProfileEvents(t *testing.T) {
	for _, typ := range []EventType{GroupCreated, GroupUpdated, GroupDeleted, GroupMemberAdded, GroupMemberRemoved, GroupRoleGranted, GroupRoleRevoked, ProfileUpdated, AvatarUpdated, AvatarRemoved} {
		if err := Validate(Event{Type: typ, TenantID: "t1", ActorKind: "user", Outcome: "ok"}); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
	}
	r, err := Row(Event{Type: ProfileUpdated, TenantID: "t1", ActorKind: "user", ActorUserID: "u1", Outcome: "ok", SubjectKind: "user", SubjectID: "u1",
		Details: map[string]any{"fields": []string{"first_name", "phone"}, "phone": "+385911234567", "first_name": "Dana", "last_name": "K", "display_name": "Dana K"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	js := string(r.Details)
	for _, leak := range []string{"+385", "Dana", `"K"`} {
		if strings.Contains(js, leak) {
			t.Fatalf("PII leak %q in %s", leak, js)
		}
	}
	if !strings.Contains(js, `"fields":["first_name","phone"]`) {
		t.Fatalf("field names must be kept: %s", js)
	}
}

func TestValidateAndRow(t *testing.T) {
	good := Event{Type: SigninFailed, TenantID: "t1", ActorKind: "user", ActorUserID: "u1", Outcome: "refused", Reason: "invalid_credentials",
		CorrelationID: "c1", Details: map[string]any{"attempt": 3, "password": "hunter2", "reset_token": "abc", "api_key": "k", "ip": "hashed"}}
	r, err := Row(good, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	js := string(r.Details)
	for _, leak := range []string{"hunter2", "abc", `"k"`} {
		if strings.Contains(js, leak) {
			t.Fatalf("leak %q in %s", leak, js)
		}
	}
	if !strings.Contains(js, `"attempt":3`) || !strings.Contains(js, `"ip":"hashed"`) || strings.Count(js, "[REDACTED]") != 3 {
		t.Fatalf("details %s", js)
	}
	if r.ActorUserID == nil || *r.ActorUserID != "u1" || r.SubjectID != nil {
		t.Fatal("nullable ids")
	}
	for _, bad := range []Event{
		{Type: "made_up", TenantID: "t", ActorKind: "user", Outcome: "ok"},
		{Type: SigninOK, ActorKind: "user", Outcome: "ok"},
		{Type: SigninOK, TenantID: "t", ActorKind: "user", Outcome: "maybe"},
		{Type: SigninOK, TenantID: "t", ActorKind: "robot", Outcome: "ok"},
	} {
		if err := Validate(bad); err == nil {
			t.Fatalf("expected error for %+v", bad)
		}
	}
}

func TestWriterBatchesAndNeverBlocks(t *testing.T) {
	ins := &fakeIns{}
	var errs []error
	var mu sync.Mutex
	w := NewWriter(ins, func(err error) { mu.Lock(); errs = append(errs, err); mu.Unlock() })
	for i := 0; i < 450; i++ {
		if err := w.Emit(Event{Type: SigninOK, TenantID: "t1", ActorKind: "user", Outcome: "ok", CorrelationID: "c"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Emit(Event{Type: "nope"}); err == nil {
		t.Fatal("invalid event must be rejected")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && ins.n() < 450 {
		time.Sleep(20 * time.Millisecond)
	}
	if ins.n() != 450 {
		t.Fatalf("rows %d", ins.n())
	}
	w.Close()
	w.Close()
	if err := w.Emit(Event{Type: SigninOK, TenantID: "t1", ActorKind: "user", Outcome: "ok"}); err == nil || w.Dropped() != 1 {
		t.Fatal("emit after close")
	}
	// Insert failures are reported, not fatal.
	f := &fakeIns{fail: true}
	w2 := NewWriter(f, func(err error) { mu.Lock(); errs = append(errs, err); mu.Unlock() })
	_ = w2.Emit(Event{Type: SigninOK, TenantID: "t1", ActorKind: "user", Outcome: "ok"})
	w2.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(errs) == 0 {
		t.Fatal("expected insert error report")
	}
}
