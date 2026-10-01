package password

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
)

// RecoveryLifetime bounds a reset link.
const RecoveryLifetime = 30 * time.Minute

// RecoveryValidFor is RecoveryLifetime as the recovery message states it.
const RecoveryValidFor = "30 minutes"

// ResetPath is the console route that completes a recovery.
const ResetPath = "/console/reset"

// ErrInvalidToken means the reset token is unknown, used or expired.
var ErrInvalidToken = errors.New("invalid_token")

// RecoveryStore is what recovery needs.
type RecoveryStore interface {
	TenantBySlug(ctx context.Context, slug string) (store.Tenant, error)
	Tenant(ctx context.Context, tenantID string) (store.Tenant, error)
	UserByEmail(ctx context.Context, tenantID, email string) (store.User, error)
	InsertRecoveryRequest(ctx context.Context, r store.RecoveryRequest, ipHash string) error
	PeekRecovery(ctx context.Context, hash string) (store.RecoveryRequest, error)
	UseRecoveryRequest(ctx context.Context, hash string) (store.RecoveryRequest, error)
	SetPassword(ctx context.Context, tenantID, userID, hash string) error
	Enqueue(ctx context.Context, it store.OutboxItem) error
}

// Recovery implements forgotten-password flows.
type Recovery struct {
	st       RecoveryStore
	outbox   *email.Outbox
	sessions *session.Manager
	audit    *audit.Writer
	issuer   string
	pad      func(time.Time)
	now      func() time.Time
}

// NewRecovery wires the service.
func NewRecovery(st RecoveryStore, ob *email.Outbox, sm *session.Manager, a *audit.Writer, issuer string) *Recovery {
	return &Recovery{st: st, outbox: ob, sessions: sm, audit: a, issuer: issuer, pad: Pad, now: time.Now}
}

// SetPad overrides the timing pad (tests only).
func (r *Recovery) SetPad(f func(time.Time)) { r.pad = f }

// Request queues a reset link when the account exists and is active. It
// always succeeds from the caller's point of view and takes the same time.
func (r *Recovery) Request(ctx context.Context, tenantSlug, emailAddr, ipHash string) error {
	start := r.now()
	defer r.pad(start)
	addr := strings.ToLower(strings.TrimSpace(emailAddr))
	// No tenant given: take it from the e-mail domain, as sign-in does.
	if strings.TrimSpace(tenantSlug) == "" {
		tenantSlug, _ = tenant.SlugFromEmail(addr)
	}
	slug, err := tenant.ParseSlug(tenantSlug)
	if err != nil {
		return nil
	}
	t, err := r.st.TenantBySlug(ctx, slug)
	if err != nil || t.Status != "active" {
		return nil
	}
	u, err := r.st.UserByEmail(ctx, t.ID, addr)
	if err != nil || u.Status != "active" {
		r.emit(audit.Event{Type: audit.RecoveryRequested, TenantID: t.ID, ActorKind: "user", Outcome: "refused", Reason: "unknown_account", OriginIPHash: ipHash})
		return nil
	}
	tok, err := crypto.RandomToken(32)
	if err != nil {
		return nil
	}
	req := store.RecoveryRequest{ID: store.NewID(), TenantID: t.ID, UserID: u.ID, TokenHash: crypto.HashToken(tok), ExpiresAt: r.now().Add(RecoveryLifetime)}
	if err := r.st.InsertRecoveryRequest(ctx, req, ipHash); err != nil {
		return nil
	}
	blob, err := r.outbox.Encode(addr, email.Recovery(r.issuer+ResetPath+"?token="+tok, RecoveryValidFor))
	if err != nil {
		return nil
	}
	_ = r.st.Enqueue(ctx, store.OutboxItem{ID: store.NewID(), TenantID: t.ID, Kind: "recovery", ToEmail: addr, PayloadEnc: blob, NextAttemptAt: r.now()})
	r.emit(audit.Event{Type: audit.RecoveryRequested, TenantID: t.ID, ActorKind: "user", ActorUserID: u.ID, Outcome: "ok", OriginIPHash: ipHash})
	return nil
}

// peek resolves an unused, unexpired token to its request and policy
// without consuming it.
func (r *Recovery) peek(ctx context.Context, token string) (store.RecoveryRequest, tenant.Policy, error) {
	if token == "" || len(token) > 256 {
		return store.RecoveryRequest{}, tenant.Policy{}, ErrInvalidToken
	}
	req, err := r.st.PeekRecovery(ctx, crypto.HashToken(token))
	if err != nil {
		return store.RecoveryRequest{}, tenant.Policy{}, ErrInvalidToken
	}
	t, err := r.st.Tenant(ctx, req.TenantID)
	if err != nil || t.Status != "active" {
		return store.RecoveryRequest{}, tenant.Policy{}, ErrInvalidToken
	}
	pol, err := tenantPolicy(t)
	return req, pol, err
}

// Requirements returns the password rules that Complete will apply for a
// still-valid token. The token is not consumed.
func (r *Recovery) Requirements(ctx context.Context, token string) (Requirements, error) {
	_, pol, err := r.peek(ctx, token)
	if err != nil {
		return Requirements{}, err
	}
	return RequirementsFor(pol), nil
}

// Complete sets a new password from a single-use token and ends every
// session of the user.
func (r *Recovery) Complete(ctx context.Context, token, next string) error {
	req, pol, err := r.peek(ctx, token)
	if err != nil {
		return err
	}
	hash := crypto.HashToken(token)
	if err := Check(pol, next); err != nil {
		return err
	}
	if _, err := r.st.UseRecoveryRequest(ctx, hash); err != nil {
		return ErrInvalidToken
	}
	h, err := Hash(next)
	if err != nil {
		return err
	}
	if err := r.st.SetPassword(ctx, req.TenantID, req.UserID, h); err != nil {
		return err
	}
	if err := r.sessions.RevokeUser(ctx, req.TenantID, req.UserID, session.ReasonPassword, ""); err != nil {
		return err
	}
	r.emit(audit.Event{Type: audit.RecoveryCompleted, TenantID: req.TenantID, ActorKind: "user", ActorUserID: req.UserID, Outcome: "ok"})
	return nil
}

func (r *Recovery) emit(e audit.Event) {
	if r.audit != nil {
		_ = r.audit.Emit(e)
	}
}

func tenantPolicy(t store.Tenant) (tenant.Policy, error) {
	return tenant.ParsePolicy(t.Policy, t.Kind == "platform")
}
