package email

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
)

// Template keys of the notification system templates auth sends (feature 017
// research D3). notification renders and delivers them; auth only names the
// key and fills the variables.
const (
	TemplateInvite       = "auth.invite"        // link, valid_for, tenant (optional)
	TemplateAccountReset = "auth.account_reset" // link, valid_for
	TemplateRecovery     = "auth.recovery"      // link, valid_for
	// TemplateMessage carries rows queued by auth ≤ 4.1 ({subject,text}).
	TemplateMessage = "auth.message"
)

// PayloadVersion is the version written by Encode.
const PayloadVersion = 2

// templatePrefix is auth's namespace at notification: other keys are refused
// there, so they are refused here before anything is queued.
const templatePrefix = "auth."

// Payload is the encrypted outbox content: a template key and its variables.
type Payload struct {
	V        int               `json:"v"`
	Template string            `json:"template"`
	Vars     map[string]string `json:"vars"`
}

// Link is the secret link variable (empty when the template has none).
func (p Payload) Link() string { return p.Vars["link"] }

// Invite is the invitation message (invite, resend, directory activation,
// first operator). tenant is optional and omitted when empty.
func Invite(link, validFor, tenant string) Payload {
	p := Payload{V: PayloadVersion, Template: TemplateInvite, Vars: map[string]string{"link": link, "valid_for": validFor}}
	if tenant != "" {
		p.Vars["tenant"] = tenant
	}
	return p
}

// AccountReset is the message for an account reset by an administrator.
func AccountReset(link, validFor string) Payload {
	return Payload{V: PayloadVersion, Template: TemplateAccountReset, Vars: map[string]string{"link": link, "valid_for": validFor}}
}

// Recovery is the password recovery message.
func Recovery(link, validFor string) Payload {
	return Payload{V: PayloadVersion, Template: TemplateRecovery, Vars: map[string]string{"link": link, "valid_for": validFor}}
}

// EncodePayload serialises p in the v2 shape.
func EncodePayload(p Payload) ([]byte, error) {
	if !strings.HasPrefix(p.Template, templatePrefix) || len(p.Template) == len(templatePrefix) {
		return nil, fmt.Errorf("email: template %q is outside %s*", p.Template, templatePrefix)
	}
	if p.Vars == nil {
		p.Vars = map[string]string{}
	}
	p.V = PayloadVersion
	return json.Marshal(p)
}

// DecodePayload parses a stored payload. Version 2 carries a template key; a
// payload without a version is a legacy {subject,text} row, sent with
// TemplateMessage. Anything else is refused.
func DecodePayload(js []byte) (Payload, error) {
	var raw struct {
		V        *int              `json:"v"`
		Template *string           `json:"template"`
		Vars     map[string]string `json:"vars"`
		Subject  *string           `json:"subject"`
		Text     *string           `json:"text"`
	}
	if err := json.Unmarshal(js, &raw); err != nil {
		return Payload{}, err
	}
	switch {
	case raw.V == nil:
		if (raw.Subject == nil && raw.Text == nil) || raw.Template != nil || raw.Vars != nil {
			return Payload{}, errors.New("email: payload is neither v2 nor a legacy message")
		}
		return Payload{V: PayloadVersion, Template: TemplateMessage, Vars: map[string]string{"subject": deref(raw.Subject), "text": deref(raw.Text)}}, nil
	case *raw.V == PayloadVersion:
		if raw.Subject != nil || raw.Text != nil || raw.Template == nil {
			return Payload{}, errors.New("email: malformed v2 payload")
		}
		p := Payload{V: PayloadVersion, Template: *raw.Template, Vars: raw.Vars}
		if p.Vars == nil {
			p.Vars = map[string]string{}
		}
		if !strings.HasPrefix(p.Template, templatePrefix) || len(p.Template) == len(templatePrefix) {
			return Payload{}, fmt.Errorf("email: template %q is outside %s*", p.Template, templatePrefix)
		}
		return p, nil
	default:
		return Payload{}, fmt.Errorf("email: unsupported payload version %d", *raw.V)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Item is a queued email as seen by the worker.
type Item struct {
	ID, TenantID, Kind, To string
	PayloadEnc             []byte
	Attempts               int // including the current attempt (Claim counts it)
}

// Queue abstracts the outbox table (implemented by the store; faked in tests).
// Claim returns due, unretired items, counts the attempt and schedules the
// next one with exponential backoff (30 s · 2^n, capped at 1 h).
type Queue interface {
	Claim(ctx context.Context, limit int) ([]Item, error)
	MarkSent(ctx context.Context, id string) error
	// MarkFailed retires an item for good; reason is at most MaxReasonLen.
	MarkFailed(ctx context.Context, id, reason string) error
}

// Outcome is a delivery verdict.
type Outcome int

const (
	Sent   Outcome = iota + 1 // delivered (or accepted for delivery)
	Retry                     // transient: try again later
	Failed                    // permanent: retire the message
)

func (o Outcome) String() string {
	switch o {
	case Sent:
		return "sent"
	case Retry:
		return "retry"
	case Failed:
		return "failed"
	}
	return "unknown"
}

// Message is one delivery handed to a Deliverer.
type Message struct {
	ID       string // outbox item id, the correlation id at notification
	TenantID string
	To       string
	Template string
	Vars     map[string]string
}

// Deliverer hands a message to its transport. The error explains a Retry or
// Failed outcome; it never carries variable values.
type Deliverer interface {
	Deliver(ctx context.Context, m Message) (Outcome, error)
}

// GiveUp describes a message retired without delivery. It is reported once.
type GiveUp struct {
	ID, TenantID, Kind string
	Attempts           int
	Reason             string
}

// MaxReasonLen bounds the stored and reported failure reason (characters).
const MaxReasonLen = 200

// Outbox encrypts queued payloads and drives delivery with retries.
type Outbox struct {
	env       *crypto.Envelope
	deliverer Deliverer
	queue     Queue
	max       int
	onErr     func(error)
	onGiveUp  func(GiveUp)
}

// NewOutbox wires the worker. maxAttempts bounds delivery attempts (default 8).
func NewOutbox(env *crypto.Envelope, d Deliverer, queue Queue, maxAttempts int, onErr func(error)) *Outbox {
	if maxAttempts <= 0 {
		maxAttempts = 8
	}
	if onErr == nil {
		onErr = func(error) {}
	}
	return &Outbox{env: env, deliverer: d, queue: queue, max: maxAttempts, onErr: onErr, onGiveUp: func(GiveUp) {}}
}

// OnGiveUp sets the single report made when a message is retired.
func (o *Outbox) OnGiveUp(fn func(GiveUp)) *Outbox {
	o.onGiveUp = fn
	return o
}

// Encode seals a payload for storage (bound to the recipient).
func (o *Outbox) Encode(to string, p Payload) ([]byte, error) {
	js, err := EncodePayload(p)
	if err != nil {
		return nil, err
	}
	return o.env.Encrypt(js, []byte("email:"+to))
}

// Decode opens a stored payload (v2 or legacy).
func (o *Outbox) Decode(to string, blob []byte) (Payload, error) {
	js, err := o.env.Decrypt(blob, []byte("email:"+to))
	if err != nil {
		return Payload{}, err
	}
	return DecodePayload(js)
}

// RunOnce claims due items and tries to deliver them. Returns sent count.
// A permanent failure, an unreadable payload or the last allowed attempt
// retires the item (it is never claimed again) and reports it once.
func (o *Outbox) RunOnce(ctx context.Context) (int, error) {
	items, err := o.queue.Claim(ctx, 50)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, it := range items {
		if it.Attempts > o.max {
			// Rows left behind by auth ≤ 4.1, which never retired them.
			o.retire(ctx, it, fmt.Sprintf("exceeded %d attempts", o.max))
			continue
		}
		p, err := o.Decode(it.To, it.PayloadEnc)
		if err != nil {
			// The error text is not kept: it may quote payload bytes.
			o.retire(ctx, it, "payload cannot be opened")
			continue
		}
		out, derr := o.deliverer.Deliver(ctx, Message{ID: it.ID, TenantID: it.TenantID, To: it.To, Template: p.Template, Vars: p.Vars})
		switch out {
		case Sent:
			if err := o.queue.MarkSent(ctx, it.ID); err != nil {
				o.onErr(err)
				continue
			}
			sent++
		case Failed:
			o.retire(ctx, it, reason(derr))
		default:
			if it.Attempts >= o.max {
				o.retire(ctx, it, fmt.Sprintf("gave up after %d attempts: %s", it.Attempts, reason(derr)))
				continue
			}
			o.onErr(fmt.Errorf("email: %s attempt %d (retry): %s", it.ID, it.Attempts, reason(derr)))
		}
	}
	return sent, nil
}

// retire marks the item failed and, only once that is stored, reports it.
func (o *Outbox) retire(ctx context.Context, it Item, why string) {
	why = clip(why)
	if err := o.queue.MarkFailed(ctx, it.ID, why); err != nil {
		o.onErr(fmt.Errorf("email: %s: retire: %w", it.ID, err))
		return
	}
	o.onGiveUp(GiveUp{ID: it.ID, TenantID: it.TenantID, Kind: it.Kind, Attempts: it.Attempts, Reason: why})
}

func reason(err error) string {
	if err == nil {
		return "no reason given"
	}
	return err.Error()
}

// clip bounds a reason to MaxReasonLen characters.
func clip(s string) string {
	r := []rune(s)
	if len(r) <= MaxReasonLen {
		return s
	}
	return string(r[:MaxReasonLen])
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
