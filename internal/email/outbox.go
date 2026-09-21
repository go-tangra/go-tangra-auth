package email

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-freya/freya/services/auth/internal/crypto"
)

// Payload is the encrypted outbox content.
type Payload struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
}

// Item is a queued email as seen by the worker.
type Item struct {
	ID, TenantID, Kind, To string
	PayloadEnc             []byte
	Attempts               int
}

// Queue abstracts the outbox table (implemented by the store; faked in tests).
type Queue interface {
	Claim(ctx context.Context, limit int, backoff time.Duration) ([]Item, error)
	MarkSent(ctx context.Context, id string) error
}

// Outbox encrypts queued payloads and drives delivery with retries.
type Outbox struct {
	env    *crypto.Envelope
	sender Sender
	queue  Queue
	max    int
	onErr  func(error)
}

// NewOutbox wires the worker. maxAttempts bounds retries (default 8).
func NewOutbox(env *crypto.Envelope, sender Sender, queue Queue, maxAttempts int, onErr func(error)) *Outbox {
	if maxAttempts <= 0 {
		maxAttempts = 8
	}
	if onErr == nil {
		onErr = func(error) {}
	}
	return &Outbox{env: env, sender: sender, queue: queue, max: maxAttempts, onErr: onErr}
}

// Encode seals a payload for storage (bound to the recipient).
func (o *Outbox) Encode(to string, p Payload) ([]byte, error) {
	js, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return o.env.Encrypt(js, []byte("email:"+to))
}

// Decode opens a stored payload.
func (o *Outbox) Decode(to string, blob []byte) (Payload, error) {
	js, err := o.env.Decrypt(blob, []byte("email:"+to))
	if err != nil {
		return Payload{}, err
	}
	var p Payload
	if err := json.Unmarshal(js, &p); err != nil {
		return Payload{}, err
	}
	return p, nil
}

// Backoff for attempt n: 30s, 1m, 2m, ... capped at 1h.
func Backoff(attempt int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempt && d < time.Hour; i++ {
		d *= 2
	}
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

// RunOnce claims due items and tries to deliver them. Returns sent count.
func (o *Outbox) RunOnce(ctx context.Context) (int, error) {
	items, err := o.queue.Claim(ctx, 50, Backoff(1))
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, it := range items {
		if it.Attempts > o.max {
			o.onErr(fmt.Errorf("email: %s exceeded %d attempts", it.ID, o.max))
			continue
		}
		p, err := o.Decode(it.To, it.PayloadEnc)
		if err != nil {
			o.onErr(fmt.Errorf("email: %s: %w", it.ID, err))
			continue
		}
		if err := o.sender.Send(ctx, Message{To: it.To, Subject: p.Subject, Text: p.Text}); err != nil {
			o.onErr(fmt.Errorf("email: %s attempt %d: %w", it.ID, it.Attempts, err))
			continue
		}
		if err := o.queue.MarkSent(ctx, it.ID); err != nil {
			o.onErr(err)
			continue
		}
		sent++
	}
	return sent, nil
}

// Run polls until ctx is done.
func (o *Outbox) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := o.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
				o.onErr(err)
			}
		}
	}
}
