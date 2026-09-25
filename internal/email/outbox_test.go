package email

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
)

type fakeQueue struct {
	items  []Item
	sent   []string
	failed map[string]string
	failOn string // MarkFailed error for this id
}

func (q *fakeQueue) Claim(_ context.Context, _ int) ([]Item, error) {
	out := q.items
	q.items = nil
	for i := range out {
		out[i].Attempts++
	}
	return out, nil
}
func (q *fakeQueue) MarkSent(_ context.Context, id string) error {
	q.sent = append(q.sent, id)
	return nil
}
func (q *fakeQueue) MarkFailed(_ context.Context, id, reason string) error {
	if id == q.failOn {
		return errors.New("db down")
	}
	if q.failed == nil {
		q.failed = map[string]string{}
	}
	q.failed[id] = reason
	return nil
}

// fakeDeliverer answers with a fixed outcome per recipient (default Sent).
type fakeDeliverer struct {
	msgs    []Message
	outcome map[string]Outcome
}

func (d *fakeDeliverer) Deliver(_ context.Context, m Message) (Outcome, error) {
	d.msgs = append(d.msgs, m)
	switch o := d.outcome[m.To]; o {
	case 0, Sent:
		return Sent, nil
	default:
		return o, errors.New("relay said " + o.String())
	}
}

func testEnv(t *testing.T) *crypto.Envelope {
	t.Helper()
	env, err := crypto.NewEnvelope(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestPayloadV2RoundTripAndAAD(t *testing.T) {
	ob := NewOutbox(testEnv(t), nil, nil, 3, nil)
	p := Invite("https://auth/accept?token=SECRET", "72 hours", "Acme")
	if p.V != 2 || p.Template != TemplateInvite || p.Vars["link"] != "https://auth/accept?token=SECRET" || p.Vars["valid_for"] != "72 hours" || p.Vars["tenant"] != "Acme" {
		t.Fatalf("invite payload %+v", p)
	}
	blob, err := ob.Encode("a@x.test", p)
	if err != nil || bytes.Contains(blob, []byte("SECRET")) {
		t.Fatalf("payload not encrypted: %v", err)
	}
	got, err := ob.Decode("a@x.test", blob)
	if err != nil || got.Template != TemplateInvite || got.Link() != p.Vars["link"] || len(got.Vars) != 3 {
		t.Fatalf("round trip %+v %v", got, err)
	}
	if _, err := ob.Decode("b@x.test", blob); err == nil {
		t.Fatal("payload must be bound to the recipient")
	}
	// The AAD is the pre-017 one: a row sealed by auth ≤ 4.1 still opens and
	// is sent with the auth.message template.
	legacy, _ := testEnv(t).Encrypt([]byte(`{"subject":"Reset your password","text":"Use https://x/?token=T"}`), []byte("email:a@x.test"))
	got, err = ob.Decode("a@x.test", legacy)
	if err != nil || got.Template != TemplateMessage || got.Vars["subject"] != "Reset your password" || got.Vars["text"] != "Use https://x/?token=T" {
		t.Fatalf("legacy row %+v %v", got, err)
	}
	if _, err := ob.Encode("a@x.test", Payload{V: 2, Template: "warden.share"}); err == nil {
		t.Fatal("a template outside auth. must not be queued")
	}
}

func TestPayloadConstructors(t *testing.T) {
	if p := Invite("l", "7 days", ""); len(p.Vars) != 2 || p.Vars["tenant"] != "" {
		t.Fatalf("an empty tenant is omitted: %+v", p)
	}
	if p := AccountReset("l", "7 days"); p.Template != TemplateAccountReset || p.Vars["link"] != "l" || p.Vars["valid_for"] != "7 days" {
		t.Fatalf("reset %+v", p)
	}
	if p := Recovery("l", "30 minutes"); p.Template != TemplateRecovery || p.Link() != "l" || p.Vars["valid_for"] != "30 minutes" {
		t.Fatalf("recovery %+v", p)
	}
}

func TestDecodePayload(t *testing.T) {
	ok := map[string]Payload{
		`{"v":2,"template":"auth.invite","vars":{"link":"L"}}`: {V: 2, Template: TemplateInvite, Vars: map[string]string{"link": "L"}},
		`{"v":2,"template":"auth.recovery"}`:                   {V: 2, Template: TemplateRecovery, Vars: map[string]string{}},
		`{"subject":"S","text":"T"}`:                           {V: 2, Template: TemplateMessage, Vars: map[string]string{"subject": "S", "text": "T"}},
		`{"text":"T"}`:                                         {V: 2, Template: TemplateMessage, Vars: map[string]string{"subject": "", "text": "T"}},
	}
	for in, want := range ok {
		got, err := DecodePayload([]byte(in))
		if err != nil || got.V != want.V || got.Template != want.Template || len(got.Vars) != len(want.Vars) {
			t.Fatalf("%s → %+v %v", in, got, err)
		}
		for k, v := range want.Vars {
			if got.Vars[k] != v {
				t.Fatalf("%s: var %s = %q", in, k, got.Vars[k])
			}
		}
	}
	for _, in := range []string{
		``, `nope`, `[]`, `{}`, `{"v":null}`,
		`{"v":3,"template":"auth.invite"}`,
		`{"v":2}`,
		`{"v":2,"template":"warden.share"}`,
		`{"v":2,"template":"auth.invite","subject":"S"}`,
		`{"v":1,"subject":"S","text":"T"}`,
		`{"subject":"S","text":"T","vars":{"link":"L"}}`,
	} {
		if p, err := DecodePayload([]byte(in)); err == nil {
			t.Fatalf("%q must be refused, got %+v", in, p)
		}
	}
	// EncodePayload writes the v2 shape only.
	js, err := EncodePayload(Recovery("L", "30 minutes"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	_ = json.Unmarshal(js, &raw)
	if raw["v"] != float64(2) || raw["template"] != TemplateRecovery || raw["subject"] != nil || len(raw) != 3 {
		t.Fatalf("v2 shape %s", js)
	}
}

func TestOutboxDeliversAndRetires(t *testing.T) {
	q := &fakeQueue{}
	d := &fakeDeliverer{outcome: map[string]Outcome{"retry@x.test": Retry, "perm@x.test": Failed}}
	var errs []error
	var reports []GiveUp
	ob := NewOutbox(testEnv(t), d, q, 3, func(err error) { errs = append(errs, err) }).OnGiveUp(func(g GiveUp) { reports = append(reports, g) })
	blob := func(to string) []byte {
		b, err := ob.Encode(to, Invite("https://auth/accept?token=SECRET", "72 hours", ""))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	q.items = []Item{
		{ID: "sent", TenantID: "t1", Kind: "invite", To: "a@x.test", PayloadEnc: blob("a@x.test")},
		{ID: "retry", TenantID: "t1", Kind: "invite", To: "retry@x.test", PayloadEnc: blob("retry@x.test")},
		{ID: "perm", TenantID: "t1", Kind: "recovery", To: "perm@x.test", PayloadEnc: blob("perm@x.test")},
		{ID: "garbage", TenantID: "t1", Kind: "invite", To: "a@x.test", PayloadEnc: []byte("garbage")},
		{ID: "old", TenantID: "t1", Kind: "invite", To: "a@x.test", PayloadEnc: blob("a@x.test"), Attempts: 7},
	}
	n, err := ob.RunOnce(context.Background())
	if err != nil || n != 1 || len(q.sent) != 1 || q.sent[0] != "sent" {
		t.Fatalf("n=%d err=%v sent=%v", n, err, q.sent)
	}
	m := d.msgs[0]
	if m.ID != "sent" || m.TenantID != "t1" || m.To != "a@x.test" || m.Template != TemplateInvite || m.Vars["link"] != "https://auth/accept?token=SECRET" {
		t.Fatalf("delivery %+v", m)
	}
	// The row past the maximum and the undecodable row are retired without a
	// delivery attempt.
	if len(d.msgs) != 3 {
		t.Fatalf("deliveries %d", len(d.msgs))
	}
	if len(q.failed) != 3 || q.failed["perm"] == "" || q.failed["garbage"] == "" || q.failed["old"] == "" {
		t.Fatalf("retired %v", q.failed)
	}
	if len(reports) != 3 {
		t.Fatalf("one report per retired row, got %+v", reports)
	}
	for _, r := range reports {
		if r.TenantID != "t1" || r.Reason == "" || strings.Contains(r.Reason, "SECRET") {
			t.Fatalf("report %+v", r)
		}
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "retry") {
		t.Fatalf("the retryable failure is logged: %v", errs)
	}
	// The retryable row stays pending; attempt 3 (= max) retires it once.
	q.items = []Item{{ID: "retry", TenantID: "t1", Kind: "invite", To: "retry@x.test", PayloadEnc: blob("retry@x.test"), Attempts: 2}}
	if _, err := ob.RunOnce(context.Background()); err != nil || q.failed["retry"] == "" || len(reports) != 4 {
		t.Fatalf("attempt limit: failed=%v reports=%d", q.failed, len(reports))
	}
	if r := reports[3]; r.ID != "retry" || r.Kind != "invite" || r.Attempts != 3 || !strings.Contains(r.Reason, "3 attempts") {
		t.Fatalf("give-up report %+v", r)
	}
	// A retired row is never claimed again, so a later pass reports nothing.
	if _, err := ob.RunOnce(context.Background()); err != nil || len(reports) != 4 {
		t.Fatalf("no re-report: %d", len(reports))
	}
	// The report follows a successful retirement only.
	q.failOn = "perm2"
	q.items = []Item{{ID: "perm2", TenantID: "t1", To: "perm@x.test", PayloadEnc: blob("perm@x.test")}}
	if _, err := ob.RunOnce(context.Background()); err != nil || len(reports) != 4 || len(errs) != 2 {
		t.Fatalf("report without retirement: %d %v", len(reports), errs)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	ob.Run(ctx, 5*time.Millisecond)
}

func TestClip(t *testing.T) {
	if got := clip(strings.Repeat("é", 300)); len([]rune(got)) != MaxReasonLen {
		t.Fatalf("clip %d", len([]rune(got)))
	}
	if clip("short") != "short" {
		t.Fatal("short reason unchanged")
	}
}

type claimErrQueue struct{ fakeQueue }

func (*claimErrQueue) Claim(context.Context, int) ([]Item, error) { return nil, errors.New("db down") }

type markSentErrQueue struct{ fakeQueue }

func (*markSentErrQueue) MarkSent(context.Context, string) error { return errors.New("db down") }

func TestOutboxQueueErrors(t *testing.T) {
	var errs []error
	ob := NewOutbox(testEnv(t), &fakeDeliverer{}, &claimErrQueue{}, 0, func(err error) { errs = append(errs, err) })
	if _, err := ob.RunOnce(context.Background()); err == nil {
		t.Fatal("claim error must surface")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	ob.Run(ctx, 5*time.Millisecond)
	if len(errs) == 0 {
		t.Fatal("Run reports claim errors")
	}
	// A sent message whose row cannot be marked is not counted.
	q := &markSentErrQueue{}
	ob = NewOutbox(testEnv(t), &fakeDeliverer{}, q, 0, nil)
	b, _ := ob.Encode("a@x.test", Recovery("l", "30 minutes"))
	q.items = []Item{{ID: "1", To: "a@x.test", PayloadEnc: b}}
	if n, err := ob.RunOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if Retry.String() != "retry" || Sent.String() != "sent" || Failed.String() != "failed" || Outcome(0).String() != "unknown" {
		t.Fatal("outcome names")
	}
}

type silentDeliverer struct{}

func (silentDeliverer) Deliver(context.Context, Message) (Outcome, error) { return Failed, nil }

func TestOutboxFailureWithoutReason(t *testing.T) {
	q := &fakeQueue{}
	ob := NewOutbox(testEnv(t), silentDeliverer{}, q, 0, nil)
	b, _ := ob.Encode("a@x.test", Payload{Template: "auth.custom"}) // no vars: stored as {}
	q.items = []Item{{ID: "1", To: "a@x.test", PayloadEnc: b}}
	if _, err := ob.RunOnce(context.Background()); err != nil || q.failed["1"] != "no reason given" {
		t.Fatalf("failed=%v err=%v", q.failed, err)
	}
}
