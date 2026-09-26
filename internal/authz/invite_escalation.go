package authz

import (
	"context"

	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// InviteEscalation is the grant check for invitations and activations
// (feature 016): the roles must pass Assigner.MayAssign and the groups
// Groups.MayJoin. It satisfies invite.Escalation.
type InviteEscalation struct {
	Assigner *Assigner
	Groups   *Groups
}

// MayAssign checks roles first, then groups; it writes nothing. Operators
// (tenant creation invites the first owner under an operator grant) and
// system actors pass once the tenant guard admits them, except for retired
// module roles, which nobody may newly assign (feature 019).
func (e InviteEscalation) MayAssign(ctx context.Context, actor tenantctx.Actor, tenantID string, roleIDs, groupIDs []string) error {
	if actor.Kind == tenantctx.KindOperator || actor.Kind == tenantctx.KindSystem {
		if err := e.Assigner.authz.guard.Require(ctx, tenantID); err != nil {
			return err
		}
		roles, err := e.Assigner.st.RolesByID(ctx, tenantID, dedupe(roleIDs))
		if err != nil {
			return err
		}
		return refuseRetired(roles)
	}
	if err := e.Assigner.MayAssign(ctx, actor, tenantID, roleIDs); err != nil {
		return err
	}
	return e.Groups.MayJoin(ctx, actor, tenantID, groupIDs)
}
