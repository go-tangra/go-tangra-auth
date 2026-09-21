package password

import (
	"context"
	"errors"
	"time"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// ErrCurrent means the current password did not verify.
var ErrCurrent = errors.New("invalid_credentials")

// ChangeStore is what a password change needs.
type ChangeStore interface {
	User(ctx context.Context, tenantID, userID string) (store.User, error)
	Tenant(ctx context.Context, tenantID string) (store.Tenant, error)
	SetPassword(ctx context.Context, tenantID, userID, hash string) error
}

// Changer changes passwords for signed-in users.
type Changer struct {
	st       ChangeStore
	sessions *session.Manager
	audit    *audit.Writer
	pad      func(time.Time)
	now      func() time.Time
}

// NewChanger wires the service.
func NewChanger(st ChangeStore, sm *session.Manager, a *audit.Writer) *Changer {
	return &Changer{st: st, sessions: sm, audit: a, pad: Pad, now: time.Now}
}

// SetPad overrides the timing pad (tests only).
func (c *Changer) SetPad(f func(time.Time)) { c.pad = f }

// Change verifies the current password, applies the policy, stores the new
// hash and ends every other session of the user.
func (c *Changer) Change(ctx context.Context, actor tenantctx.Actor, current, next string) error {
	start := c.now()
	defer c.pad(start)
	u, err := c.st.User(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return err
	}
	hash := ""
	if u.PasswordHash != nil {
		hash = *u.PasswordHash
	}
	if ok, _ := Verify(current, hash); !ok {
		c.emit(audit.Event{Type: audit.PasswordChanged, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: "wrong_current_password"})
		return ErrCurrent
	}
	t, err := c.st.Tenant(ctx, actor.TenantID)
	if err != nil {
		return err
	}
	pol, err := tenantPolicy(t)
	if err != nil {
		return err
	}
	if err := Check(pol, next); err != nil {
		return err
	}
	h, err := Hash(next)
	if err != nil {
		return err
	}
	if err := c.st.SetPassword(ctx, actor.TenantID, actor.UserID, h); err != nil {
		return err
	}
	if err := c.sessions.RevokeUser(ctx, actor.TenantID, actor.UserID, session.ReasonPassword, actor.SessionID); err != nil {
		return err
	}
	c.emit(audit.Event{Type: audit.PasswordChanged, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok"})
	return nil
}

func (c *Changer) emit(e audit.Event) {
	if c.audit != nil {
		_ = c.audit.Emit(e)
	}
}
