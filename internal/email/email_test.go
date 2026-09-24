package email

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
)

type fakeQueue struct {
	items []Item
	sent  []string
}

func (q *fakeQueue) Claim(_ context.Context, _ int, _ time.Duration) ([]Item, error) {
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

type fakeSender struct {
	msgs []Message
	fail bool
}

func (s *fakeSender) Send(_ context.Context, m Message) error {
	if s.fail {
		return errors.New("smtp down")
	}
	s.msgs = append(s.msgs, m)
	return nil
}

func TestOutboxEncryptsAndDelivers(t *testing.T) {
	env, _ := crypto.NewEnvelope(bytes.Repeat([]byte{1}, 32))
	q := &fakeQueue{}
	s := &fakeSender{}
	var errs []error
	ob := NewOutbox(env, s, q, 3, func(err error) { errs = append(errs, err) })
	blob, err := ob.Encode("a@x.test", Payload{Subject: "Invite", Text: "https://auth/accept?token=SECRET"})
	if err != nil || bytes.Contains(blob, []byte("SECRET")) {
		t.Fatalf("payload not encrypted: %v", err)
	}
	if _, err := ob.Decode("b@x.test", blob); err == nil {
		t.Fatal("payload must be bound to the recipient")
	}
	q.items = []Item{{ID: "1", To: "a@x.test", PayloadEnc: blob}, {ID: "2", To: "a@x.test", PayloadEnc: []byte("garbage")}, {ID: "3", To: "a@x.test", PayloadEnc: blob, Attempts: 5}}
	n, err := ob.RunOnce(context.Background())
	if err != nil || n != 1 || len(s.msgs) != 1 || s.msgs[0].Text != "https://auth/accept?token=SECRET" || len(q.sent) != 1 {
		t.Fatalf("n=%d err=%v msgs=%d sent=%v", n, err, len(s.msgs), q.sent)
	}
	if len(errs) != 2 {
		t.Fatalf("expected a decode error and an attempts error, got %v", errs)
	}
	// Failure keeps the item unsent.
	s.fail = true
	q.items = []Item{{ID: "4", To: "a@x.test", PayloadEnc: blob}}
	n, _ = ob.RunOnce(context.Background())
	if n != 0 || len(q.sent) != 1 {
		t.Fatal("failed sends must not be marked")
	}
	if Backoff(1) != 30*time.Second || Backoff(2) != time.Minute || Backoff(20) != time.Hour {
		t.Fatal("backoff")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	ob.Run(ctx, 5*time.Millisecond)
}

func TestSenders(t *testing.T) {
	if _, err := NewSMTP(SMTPConfig{}); err == nil {
		t.Fatal("config required")
	}
	s, _ := NewSMTP(SMTPConfig{Host: "mail", Port: 25, From: "a@x"})
	if err := s.Send(context.Background(), Message{To: "b@x"}); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("plaintext port must be refused: %v", err)
	}
	var buf bytes.Buffer
	l := LogSink{Log: slog.New(slog.NewTextHandler(&buf, nil))}
	if err := l.Send(context.Background(), Message{To: "b@x", Subject: "s\r\nX: injected", Text: "t"}); err != nil {
		t.Fatal(err)
	}
	if sanitizeHeader("a\r\nb") != "a  b" {
		t.Fatal("header sanitize")
	}
}

func TestSMTPSendFailure(t *testing.T) {
	s, err := NewSMTP(SMTPConfig{Host: "127.0.0.1", Port: 1, From: "a@x", Username: "u", Password: "p", AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), Message{To: "b@x", Subject: "s", Text: "t"}); err == nil {
		t.Fatal("closed port must fail")
	}
}
