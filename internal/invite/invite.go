// Package invite implements invitations: creation and resend by an
// administrator (always acknowledged identically, so e-mail existence is never
// revealed), and acceptance, which sets the first password, activates the
// account and assigns the invited roles.
package invite

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/crypto"
	"github.com/go-freya/freya/services/auth/internal/email"
	"github.com/go-freya/freya/services/auth/internal/password"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenant"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
	"github.com/go-freya/freya/services/auth/internal/user"
)

// Lifetime of an invitation token.
const Lifetime = 72 * time.Hour

// Errors.
var (
	ErrInvalidToken = errors.New("invalid_token")
	ErrPolicy       = errors.New("password_policy")
	ErrBadEmail     = errors.New("validation_failed")
)

// Tx is the per-request persistence surface (one transaction on the database).
type Tx interface {
	Tenant(ctx context.Context, tenantID string) (store.Tenant, error)
	UserByEmail(ctx context.Context, tenantID, email string) (store.User, error)
	// Feature 016: activation loads the imported row by id; UserAnyTenant is
	// used only under system scope to audit cross-tenant ids.
	UserByID(ctx context.Context, tenantID, id string) (store.User, error)
	UserAnyTenant(ctx context.Context, id string) (store.User, error)
	InsertUser(ctx context.Context, u store.User) error
	SetPasswordHash(ctx context.Context, tenantID, userID, hash string) error
	UpdateUserStatus(ctx context.Context, tenantID, userID, status string) error
	InsertInvitation(ctx context.Context, i store.Invitation) error
	Invitation(ctx context.Context, tenantID, id string) (store.Invitation, error)
	InvitationByHash(ctx context.Context, hash string) (store.Invitation, error)
	RotateInvitation(ctx context.Context, tenantID, id, hash string, exp time.Time) error
	MarkInvitationAccepted(ctx context.Context, id string) error
	RolesByID(ctx context.Context, tenantID string, ids []string) ([]store.Role, error)
	ReplaceBindings(ctx context.Context, tenantID, userID, grantedBy string, roleIDs []string) error
	Enqueue(ctx context.Context, it store.OutboxItem) error
	// Feature 004: invitations may name groups.
	GetGroup(ctx context.Context, tenantID, id string) (store.Group, error)
	AddGroupMembers(ctx context.Context, tenantID, groupID, addedBy string, userIDs []string) (int, error)
	Roles(ctx context.Context, tenantID, userID string) ([]string, error) // effective roles
}

// Params describe an invitation (feature 004 adds groups and names).
type Params struct {
	Email               string
	RoleIDs             []string
	GroupIDs            []string
	FirstName, LastName string
}

// GroupsMax bounds the groups an invitation may name.
const GroupsMax = 50

// Store opens a transaction under a scope. Tx is passed as any so the
// in-memory store can satisfy it without a transaction type of its own.
type Store interface {
	Atomic(ctx context.Context, scope store.Scope, fn func(tx any) error) error
}

// Escalation refuses roles or groups that grant more than the actor holds
// (authz.ErrSelfEscalation). It writes nothing.
type Escalation interface {
	MayAssign(ctx context.Context, actor tenantctx.Actor, tenantID string, roleIDs, groupIDs []string) error
}

// Service handles invitations.
type Service struct {
	st     Store
	outbox *email.Outbox
	authz  *authz.Client
	audit  *audit.Writer
	esc    Escalation
	issuer string
	now    func() time.Time
}

// New wires the service. issuer is the public base URL for accept links.
func New(st Store, ob *email.Outbox, az *authz.Client, a *audit.Writer, issuer string) *Service {
	return &Service{st: st, outbox: ob, authz: az, audit: a, issuer: issuer, now: time.Now}
}

// WithEscalation attaches the grant check applied to every invitation and
// activation. Without one, no check is made.
func (s *Service) WithEscalation(e Escalation) *Service {
	s.esc = e
	return s
}

// AcceptPath is the console route that completes an invitation.
const AcceptPath = "/console/invite/accept"

func normEmail(e string) (string, error) {
	e = strings.ToLower(strings.TrimSpace(e))
	at := strings.IndexByte(e, '@')
	if at <= 0 || at == len(e)-1 || strings.ContainsAny(e, " \t\r\n") || len(e) > 254 {
		return "", ErrBadEmail
	}
	return e, nil
}

// Create queues an invitation. The result is identical whether or not the
// address already has an account; an active account is never re-invited.
func (s *Service) Create(ctx context.Context, actor tenantctx.Actor, tenantID, emailAddr string, roleIDs []string) (string, error) {
	return s.CreateWith(ctx, actor, tenantID, Params{Email: emailAddr, RoleIDs: roleIDs})
}

// CreateWith is Create with groups and profile names. An e-mail that belongs
// to an imported user activates that user (feature 016); the result has the
// same shape as any other invitation.
func (s *Service) CreateWith(ctx context.Context, actor tenantctx.Actor, tenantID string, p Params) (string, error) {
	addr, err := normEmail(p.Email)
	if err != nil {
		return "", err
	}
	first, err := user.ValidateName(p.FirstName)
	if err != nil {
		return "", ErrBadEmail
	}
	last, err := user.ValidateName(p.LastName)
	if err != nil {
		return "", ErrBadEmail
	}
	if err := s.checkGrants(ctx, actor, tenantID, p); err != nil {
		return "", err
	}
	var id string
	err = s.st.Atomic(ctx, store.Scope{TenantID: tenantID}, func(raw any) error {
		tx := raw.(Tx)
		u, err := tx.UserByEmail(ctx, tenantID, addr)
		switch {
		case err == nil && u.Status == "imported":
			pp := p
			pp.FirstName, pp.LastName = orName(first, u.FirstName), orName(last, u.LastName)
			id, err = s.activate(ctx, tx, actor, tenantID, u, pp)
			return err
		case err == nil && u.Status != "invited":
			s.emit(audit.Event{Type: audit.InviteCreated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: "account_exists", SubjectKind: "user", SubjectID: u.ID})
			return nil
		}
		id, err = s.invite(ctx, tx, actor, tenantID, addr, p.RoleIDs, p.GroupIDs, first, last)
		if err != nil {
			return err
		}
		s.emit(audit.Event{Type: audit.InviteCreated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "invite", SubjectID: id})
		return nil
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func orName(given, row string) string {
	if given != "" {
		return given
	}
	return row
}

// checkGrants refuses a request naming too many, unknown or foreign roles or
// groups (ErrBadEmail), then runs the escalation check once. Nothing is
// written.
func (s *Service) checkGrants(ctx context.Context, actor tenantctx.Actor, tenantID string, p Params) error {
	if len(p.GroupIDs) > GroupsMax {
		return ErrBadEmail
	}
	err := s.st.Atomic(ctx, store.Scope{TenantID: tenantID}, func(raw any) error {
		tx := raw.(Tx)
		if _, err := tx.RolesByID(ctx, tenantID, p.RoleIDs); err != nil {
			return ErrBadEmail
		}
		for _, gid := range p.GroupIDs {
			if _, err := tx.GetGroup(ctx, tenantID, gid); err != nil {
				return ErrBadEmail
			}
		}
		return nil
	})
	if err != nil || s.esc == nil {
		return err
	}
	if err := s.esc.MayAssign(ctx, actor, tenantID, p.RoleIDs, p.GroupIDs); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrBadEmail
		}
		return err
	}
	return nil
}

// invite inserts an invitation and queues its e-mail; it returns the id.
func (s *Service) invite(ctx context.Context, tx Tx, actor tenantctx.Actor, tenantID, addr string, roleIDs, groupIDs []string, first, last string) (string, error) {
	tok, err := crypto.RandomToken(32)
	if err != nil {
		return "", err
	}
	id := store.NewID()
	inv := store.Invitation{ID: id, TenantID: tenantID, Email: addr, RoleIDs: roleIDs, TokenHash: crypto.HashToken(tok), ExpiresAt: s.now().Add(Lifetime),
		GroupIDs: groupIDs, FirstName: first, LastName: last}
	if actor.UserID != "" {
		invitedBy := actor.UserID
		inv.InvitedBy = &invitedBy
	}
	if err := tx.InsertInvitation(ctx, inv); err != nil {
		return "", err
	}
	if err := s.queue(ctx, tx, tenantID, addr, tok); err != nil {
		return "", err
	}
	return id, nil
}

// activate invites an imported user and moves the row to invited. The
// invitation is written before the status so a failed insert leaves the user
// imported.
func (s *Service) activate(ctx context.Context, tx Tx, actor tenantctx.Actor, tenantID string, u store.User, p Params) (string, error) {
	id, err := s.invite(ctx, tx, actor, tenantID, strings.ToLower(u.Email), p.RoleIDs, p.GroupIDs, p.FirstName, p.LastName)
	if err != nil {
		return "", err
	}
	if err := tx.UpdateUserStatus(ctx, tenantID, u.ID, "invited"); err != nil {
		return "", err
	}
	s.emit(audit.Event{Type: audit.InviteCreated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", Reason: "activation",
		SubjectKind: "user", SubjectID: u.ID, Details: map[string]any{"invitation_id": id}})
	return id, nil
}

// ActivateMax bounds the users one activation request may name.
const ActivateMax = 100

// Activation outcomes and per-user failure reasons.
const (
	OutcomeInvited     = "invited"
	OutcomeFailed      = "failed"
	ReasonInvalidState = "invalid_state"
	ReasonNotFound     = "not_found"
	ReasonInternal     = "internal"
)

// ActivateItem is the result for one requested user; empty strings stand for
// no value.
type ActivateItem struct {
	UserID, Outcome, InvitationID, Reason string
}

// Activate invites imported users (feature 016, D11): each moves imported →
// invited with an invitation carrying the names from its row and the given
// roles and groups. The request is refused as a whole (nil items) when it is
// malformed or grants beyond the actor; otherwise every user is handled in
// its own transaction and results follow request order.
func (s *Service) Activate(ctx context.Context, actor tenantctx.Actor, tenantID string, userIDs []string, p Params) ([]ActivateItem, error) {
	if len(userIDs) == 0 || len(userIDs) > ActivateMax {
		return nil, ErrBadEmail
	}
	seen := make(map[string]bool, len(userIDs))
	for _, uid := range userIDs {
		if seen[uid] {
			return nil, ErrBadEmail
		}
		seen[uid] = true
	}
	if err := s.checkGrants(ctx, actor, tenantID, p); err != nil {
		return nil, err
	}
	items := make([]ActivateItem, 0, len(userIDs))
	for _, uid := range userIDs {
		items = append(items, s.activateOne(ctx, actor, tenantID, uid, p))
	}
	return items, nil
}

var errInvalidState = errors.New(ReasonInvalidState)

func (s *Service) activateOne(ctx context.Context, actor tenantctx.Actor, tenantID, uid string, p Params) ActivateItem {
	it := ActivateItem{UserID: uid, Outcome: OutcomeFailed}
	var id string
	err := s.st.Atomic(ctx, store.Scope{TenantID: tenantID}, func(raw any) error {
		tx := raw.(Tx)
		u, err := tx.UserByID(ctx, tenantID, uid)
		if err != nil {
			return err
		}
		if u.Status != "imported" {
			return errInvalidState
		}
		pp := p
		pp.FirstName, pp.LastName = u.FirstName, u.LastName
		id, err = s.activate(ctx, tx, actor, tenantID, u, pp)
		return err
	})
	switch {
	case err == nil:
		it.Outcome, it.InvitationID = OutcomeInvited, id
	case errors.Is(err, errInvalidState):
		it.Reason = ReasonInvalidState
	case errors.Is(err, store.ErrNotFound):
		it.Reason = ReasonNotFound
		s.auditForeign(ctx, actor, tenantID, uid)
	default:
		it.Reason = ReasonInternal
	}
	return it
}

// auditForeign records a cross-tenant attempt when uid exists in another
// tenant. The lookup runs under system scope, outside the tenant
// transaction, and the event carries no e-mail.
func (s *Service) auditForeign(ctx context.Context, actor tenantctx.Actor, tenantID, uid string) {
	if !tenantctx.ValidTenantID(uid) {
		return
	}
	var other store.User
	err := s.st.Atomic(ctx, store.Scope{System: true}, func(raw any) error {
		var err error
		other, err = raw.(Tx).UserAnyTenant(ctx, uid)
		return err
	})
	if err != nil || other.TenantID == tenantID {
		return
	}
	s.emit(audit.Event{Type: audit.CrossTenantRefused, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: "foreign_user",
		SubjectKind: "user", SubjectID: uid, Details: map[string]any{"target_tenant": other.TenantID}})
}

// Resend rotates the token and queues the e-mail again.
func (s *Service) Resend(ctx context.Context, actor tenantctx.Actor, tenantID, id string) error {
	return s.st.Atomic(ctx, store.Scope{TenantID: tenantID}, func(raw any) error {
		tx := raw.(Tx)
		inv, err := tx.Invitation(ctx, tenantID, id)
		if err != nil || inv.AcceptedAt != nil || inv.RevokedAt != nil {
			return store.ErrNotFound
		}
		tok, err := crypto.RandomToken(32)
		if err != nil {
			return err
		}
		if err := tx.RotateInvitation(ctx, tenantID, id, crypto.HashToken(tok), s.now().Add(Lifetime)); err != nil {
			return err
		}
		if err := s.queue(ctx, tx, tenantID, inv.Email, tok); err != nil {
			return err
		}
		s.emit(audit.Event{Type: audit.InviteCreated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", Reason: "resend", SubjectKind: "invite", SubjectID: id})
		return nil
	})
}

func (s *Service) queue(ctx context.Context, tx Tx, tenantID, addr, tok string) error {
	link := s.issuer + AcceptPath + "?token=" + tok
	blob, err := s.outbox.Encode(addr, email.Payload{Subject: "You have been invited", Text: "Accept your invitation within 72 hours:\n\n" + link + "\n"})
	if err != nil {
		return err
	}
	return tx.Enqueue(ctx, store.OutboxItem{ID: store.NewID(), TenantID: tenantID, Kind: "invite", ToEmail: addr, PayloadEnc: blob, NextAttemptAt: s.now()})
}

// Accepted describes the activated account.
type Accepted struct {
	User     store.User
	Tenant   store.Tenant
	Roles    []string
	Policy   tenant.Policy
	Operator bool
}

// Accept redeems a token, applies the tenant password policy, creates or
// activates the account and assigns the invited roles (mirror rows and FGA
// tuples). The token is single-use and expires after Lifetime.
func (s *Service) Accept(ctx context.Context, token, displayName, pw string) (Accepted, error) {
	if token == "" || len(token) > 256 {
		return Accepted{}, ErrInvalidToken
	}
	hash := crypto.HashToken(token)
	var out Accepted
	var tuples []authz.Tuple
	err := s.st.Atomic(ctx, store.Scope{System: true}, func(raw any) error {
		tx := raw.(Tx)
		inv, err := tx.InvitationByHash(ctx, hash)
		if err != nil || inv.AcceptedAt != nil || inv.RevokedAt != nil || !s.now().Before(inv.ExpiresAt) {
			return ErrInvalidToken
		}
		t, err := tx.Tenant(ctx, inv.TenantID)
		if err != nil || t.Status != "active" {
			return ErrInvalidToken
		}
		pol, err := tenant.ParsePolicy(t.Policy, t.Kind == "platform")
		if err != nil {
			return err
		}
		if err := password.Check(pol, pw); err != nil {
			return errors.Join(ErrPolicy, err)
		}
		h, err := password.Hash(pw)
		if err != nil {
			return err
		}
		u, err := tx.UserByEmail(ctx, inv.TenantID, inv.Email)
		switch {
		case errors.Is(err, store.ErrNotFound):
			// Names come from the invitation; an explicit display name given at
			// acceptance wins, otherwise it derives from the names (feature 004).
			dn := strings.TrimSpace(displayName)
			explicit := dn != ""
			if dn == "" {
				dn = user.DeriveDisplayName(inv.FirstName, inv.LastName, "", inv.Email)
			}
			u = store.User{ID: store.NewID(), TenantID: inv.TenantID, Email: inv.Email, DisplayName: dn, Status: "active", PasswordHash: &h,
				FirstName: inv.FirstName, LastName: inv.LastName, DisplayNameExplicit: explicit}
			if err := tx.InsertUser(ctx, u); err != nil {
				return err
			}
		case err != nil:
			return err
		case u.Status == "invited":
			if err := tx.SetPasswordHash(ctx, inv.TenantID, u.ID, h); err != nil {
				return err
			}
			if err := tx.UpdateUserStatus(ctx, inv.TenantID, u.ID, "active"); err != nil {
				return err
			}
			u.Status, u.PasswordHash = "active", &h
		default:
			return ErrInvalidToken
		}
		roles, err := tx.RolesByID(ctx, inv.TenantID, inv.RoleIDs)
		if err != nil {
			return err
		}
		if err := tx.ReplaceBindings(ctx, inv.TenantID, u.ID, u.ID, inv.RoleIDs); err != nil {
			return err
		}
		if err := tx.MarkInvitationAccepted(ctx, inv.ID); err != nil {
			return err
		}
		tuples = append(tuples, authz.MembershipTuple(inv.TenantID, u.ID, "member"))
		// Groups named by the invitation that still exist; the rest are skipped.
		var skipped []string
		for _, gid := range inv.GroupIDs {
			if _, err := tx.GetGroup(ctx, inv.TenantID, gid); err != nil {
				skipped = append(skipped, gid)
				continue
			}
			if _, err := tx.AddGroupMembers(ctx, inv.TenantID, gid, u.ID, []string{u.ID}); err != nil {
				return err
			}
			tuples = append(tuples, authz.GroupMembershipTuple(inv.TenantID, gid, u.ID))
		}
		details := map[string]any{}
		if len(skipped) > 0 {
			details["skipped_groups"] = skipped
		}
		for _, r := range roles {
			tuples = append(tuples, authz.RoleAssignmentTuple(inv.TenantID, r.Slug, u.ID))
			if r.Slug == "owner" {
				tuples = append(tuples, authz.MembershipTuple(inv.TenantID, u.ID, "owner"))
			}
		}
		// The session starts with the effective roles (direct and through groups).
		if out.Roles, err = tx.Roles(ctx, inv.TenantID, u.ID); err != nil {
			return err
		}
		out.User, out.Tenant, out.Policy, out.Operator = u, t, pol, t.Kind == "platform"
		s.emit(audit.Event{Type: audit.InviteAccepted, TenantID: inv.TenantID, ActorKind: "user", ActorUserID: u.ID, Outcome: "ok", SubjectKind: "invite", SubjectID: inv.ID, Details: details})
		return nil
	})
	if err != nil {
		return Accepted{}, err
	}
	if out.Roles == nil {
		out.Roles = []string{}
	}
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	if err := s.authz.Write(sys, out.Tenant.ID, tuples, nil); err != nil {
		return Accepted{}, err
	}
	return out, nil
}

func (s *Service) emit(e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Emit(e)
	}
}
