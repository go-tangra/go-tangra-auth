package authz

import (
	"context"

	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// Escalation is the self-escalation guard: an actor may only grant
// permissions they hold. Owners hold everything by definition; admins and
// everyone else are checked permission by permission against the model.
type Escalation struct{ authz *Client }

// NewEscalation wires the guard.
func NewEscalation(c *Client) *Escalation { return &Escalation{authz: c} }

// MayGrant returns ErrSelfEscalation when the actor lacks any of perms.
func (e *Escalation) MayGrant(ctx context.Context, actor tenantctx.Actor, tenantID string, perms []PermissionRef) error {
	if len(perms) == 0 || hasSlug(actor.Roles, "owner") {
		return nil
	}
	if actor.Kind == tenantctx.KindSystem {
		return nil
	}
	held, err := e.authz.AllowedMany(ctx, tenantID, actor.UserID, perms)
	if err != nil {
		return err
	}
	for _, ok := range held {
		if !ok {
			return ErrSelfEscalation
		}
	}
	return nil
}
