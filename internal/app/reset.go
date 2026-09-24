package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/email"
	"github.com/go-freya/freya/services/auth/internal/httpapi"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// ResetResult is what `authsvc reset-user` prints. The accept link is the only
// way back into the account; it is also queued by e-mail.
type ResetResult struct {
	TenantID          string   `json:"tenant_id"`
	UserID            string   `json:"user_id"`
	Email             string   `json:"email"`
	Roles             []string `json:"roles"`
	InvitationID      string   `json:"invitation_id"`
	AcceptURL         string   `json:"accept_url"`
	RevokedInvitation int64    `json:"revoked_invitations"`
}

// ErrResetNotAllowed is returned for users that cannot be reset: unknown,
// imported (they must be activated instead) or deactivated (reactivate first).
var ErrResetNotAllowed = errors.New("reset: user not found or not in an active/invited state")

// ResetUser is the break-glass recovery for a user who lost their password or
// MFA device (typically the platform operator, who has no one above them to
// reset it). In one transaction it clears the password, MFA seed and recovery
// codes, returns the user to "invited", revokes their sessions and pending
// invitations, and issues a fresh invitation that keeps their current roles.
// It is a CLI-only operation: it needs direct database access and is audited.
func (a *App) ResetUser(ctx context.Context, tenantSlug, userEmail string) (ResetResult, error) {
	if tenantSlug == "" || userEmail == "" {
		return ResetResult{}, errors.New("reset: tenant and email required")
	}
	res := ResetResult{Email: userEmail}
	now := store.Now()
	var wasActive bool
	err := a.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		t, err := store.GetTenantBySlug(ctx, tx, tenantSlug)
		if err != nil {
			return fmt.Errorf("reset: tenant %q: %w", tenantSlug, err)
		}
		res.TenantID = t.ID
		u, err := store.GetUserByEmail(ctx, tx, t.ID, userEmail)
		if errors.Is(err, store.ErrNotFound) {
			return ErrResetNotAllowed
		} else if err != nil {
			return err
		}
		res.UserID = u.ID
		wasActive = u.Status == "active"
		// Keep the user's roles: accepting an invitation replaces bindings with
		// the invitation's role set.
		if res.Roles, err = store.UserRoleSlugs(ctx, tx, t.ID, u.ID); err != nil {
			return err
		}
		all, err := store.ListRoles(ctx, tx, t.ID)
		if err != nil {
			return err
		}
		bySlug := map[string]string{}
		for _, r := range all {
			bySlug[r.Slug] = r.ID
		}
		roleIDs := make([]string, 0, len(res.Roles))
		for _, s := range res.Roles {
			if id, ok := bySlug[s]; ok {
				roleIDs = append(roleIDs, id)
			}
		}
		if err := store.ResetCredentials(ctx, tx, t.ID, u.ID); errors.Is(err, store.ErrNotFound) {
			return ErrResetNotAllowed
		} else if err != nil {
			return err
		}
		if err := store.ReplaceRecoveryCodes(ctx, tx, t.ID, u.ID, nil); err != nil {
			return err
		}
		if err := store.RevokeUserSessions(ctx, tx, t.ID, u.ID, "admin_revoked", ""); err != nil {
			return err
		}
		if res.RevokedInvitation, err = store.RevokePendingInvitations(ctx, tx, t.ID, u.Email); err != nil {
			return err
		}
		tok, err := crypto.RandomToken(32)
		if err != nil {
			return err
		}
		inv := store.Invitation{ID: store.NewID(), TenantID: t.ID, Email: u.Email, RoleIDs: roleIDs,
			TokenHash: crypto.HashToken(tok), ExpiresAt: now.Add(7 * 24 * time.Hour)}
		if err := store.InsertInvitation(ctx, tx, inv); err != nil {
			return err
		}
		res.InvitationID = inv.ID
		res.AcceptURL = a.Cfg.Issuer + httpapi.ConsolePrefix + "/invite/accept?token=" + tok
		blob, err := a.Outbox.Encode(u.Email, email.Payload{Subject: "Your account was reset",
			Text: "Your password and two-factor authentication were reset by an administrator.\nSet them up again within 7 days:\n\n" + res.AcceptURL + "\n"})
		if err != nil {
			return err
		}
		return store.EnqueueOutbox(ctx, tx, store.OutboxItem{ID: store.NewID(), TenantID: t.ID, Kind: "invite", ToEmail: u.Email, PayloadEnc: blob, NextAttemptAt: now})
	})
	if err != nil {
		return ResetResult{}, err
	}
	// An accepted user holds tenant-membership and role-assignment tuples. The
	// invited state carries no authorization, and accepting the new invitation
	// writes these tuples again (OpenFGA refuses to write a duplicate), so
	// remove them now. A never-accepted invited user has none to remove.
	if wasActive {
		var removes []authz.Tuple
		removes = append(removes, authz.MembershipTuple(res.TenantID, res.UserID, "member"))
		for _, slug := range res.Roles {
			removes = append(removes, authz.RoleAssignmentTuple(res.TenantID, slug, res.UserID))
			if slug == "owner" {
				removes = append(removes, authz.MembershipTuple(res.TenantID, res.UserID, "owner"))
			}
		}
		sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
		if err := a.Authz.Write(sys, res.TenantID, nil, removes); err != nil {
			return ResetResult{}, fmt.Errorf("reset: credentials cleared but authorization tuples not removed (accepting the invitation will fail until they are): %w", err)
		}
	}
	_ = a.Audit.Emit(audit.Event{Type: audit.MFARemoved, TenantID: res.TenantID, ActorKind: "system", Outcome: "ok", Reason: "cli_reset", SubjectKind: "user", SubjectID: res.UserID})
	_ = a.Audit.Emit(audit.Event{Type: audit.SessionRevoked, TenantID: res.TenantID, ActorKind: "system", Outcome: "ok", Reason: "cli_reset", SubjectKind: "user", SubjectID: res.UserID})
	_ = a.Audit.Emit(audit.Event{Type: audit.InviteCreated, TenantID: res.TenantID, ActorKind: "system", Outcome: "ok", Reason: "cli_reset", SubjectKind: "invite", SubjectID: res.InvitationID})
	return res, nil
}
