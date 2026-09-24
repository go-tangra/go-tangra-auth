package user

import (
	"context"
	"errors"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Admin refusals.
var (
	ErrLastOwner = errors.New("last_owner")
	ErrNotFound  = store.ErrNotFound
	// ErrInvalidState refuses an operation the user's status does not allow:
	// an imported user is only activated (invitation) or removed (feature 016).
	ErrInvalidState = errors.New("invalid_state")
)

// AdminStore is what administration needs from persistence.
type AdminStore interface {
	User(ctx context.Context, tenantID, id string) (store.User, error)
	UserAnyTenant(ctx context.Context, id string) (store.User, error)
	ListUsers(ctx context.Context, tenantID, q, status string, limit int) ([]store.User, error)
	UpdateUserStatus(ctx context.Context, tenantID, id, status string) error
	Roles(ctx context.Context, tenantID, userID string) ([]string, error) // effective roles
	CountWithRole(ctx context.Context, tenantID, slug string) (int, error)
	UserGroups(ctx context.Context, tenantID, userID string) ([]store.Group, error)
	// DeleteImportedUser hard-deletes a user only while imported; any other
	// status (or a missing user) is store.ErrNotFound.
	DeleteImportedUser(ctx context.Context, tenantID, userID string) error
}

// Admin performs tenant administration of users. Every method takes the
// acting administrator from ctx and operates only inside their tenant.
type Admin struct {
	st       AdminStore
	sessions *session.Manager
	audit    *audit.Writer
}

// NewAdmin wires the service.
func NewAdmin(st AdminStore, sm *session.Manager, a *audit.Writer) *Admin {
	return &Admin{st: st, sessions: sm, audit: a}
}

// UserView is the admin listing projection (no hashes, no secrets).
type UserView struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Status      string   `json:"status"`
	MFAEnabled  bool     `json:"mfa_enabled"`
	Roles       []string `json:"roles"`
	LastSignin  *string  `json:"last_signin_at"`
	// Feature 004: profile (never the phone) and group membership.
	FirstName string     `json:"first_name"`
	LastName  string     `json:"last_name"`
	AvatarURL string     `json:"avatar_url"`
	Groups    []GroupRef `json:"groups"`
	// Feature 016: the directory origin of an imported user (never the DN)
	// and the pending invitation of an invited one; both null otherwise.
	Directory    *DirectoryOrigin `json:"directory"`
	InvitationID *string          `json:"invitation_id"`
}

// DirectoryOrigin labels where a user was imported from. ConnectionID is nil
// once the connection was deleted; ConnectionName keeps the label.
type DirectoryOrigin struct {
	ConnectionID   *string `json:"connection_id"`
	ConnectionName string  `json:"connection_name"`
	DirectoryUID   string  `json:"directory_uid"`
	LastImportedAt string  `json:"last_imported_at"`
}

// GroupRef names a group a user belongs to.
type GroupRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// List searches the actor's tenant.
func (a *Admin) List(ctx context.Context, actor tenantctx.Actor, q, status string) ([]UserView, error) {
	users, err := a.st.ListUsers(ctx, actor.TenantID, q, status, 200)
	if err != nil {
		return nil, err
	}
	out := make([]UserView, 0, len(users))
	for _, u := range users {
		roles, _ := a.st.Roles(ctx, actor.TenantID, u.ID)
		v := UserView{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Status: u.Status, MFAEnabled: u.MFAEnabled, Roles: nonNilStrings(roles),
			FirstName: u.FirstName, LastName: u.LastName, AvatarURL: tenantctx.AvatarURL(u.ID, u.AvatarID), Groups: []GroupRef{},
			InvitationID: u.InvitationID}
		if l := u.Directory; l != nil {
			v.Directory = &DirectoryOrigin{ConnectionID: l.ConnectionID, ConnectionName: l.ConnectionName, DirectoryUID: l.DirectoryUID,
				LastImportedAt: l.LastImportedAt.UTC().Format("2006-01-02T15:04:05Z07:00")}
		}
		if groups, err := a.st.UserGroups(ctx, actor.TenantID, u.ID); err == nil {
			for _, g := range groups {
				v.Groups = append(v.Groups, GroupRef{ID: g.ID, Name: g.Name})
			}
		}
		if u.LastSigninAt != nil {
			s := u.LastSigninAt.UTC().Format("2006-01-02T15:04:05Z07:00")
			v.LastSignin = &s
		}
		out = append(out, v)
	}
	return out, nil
}

// Lookup is lookup for callers outside the package.
func (a *Admin) Lookup(ctx context.Context, actor tenantctx.Actor, uid string) (store.User, error) {
	return a.lookup(ctx, actor, uid)
}

// lookup finds a user in the actor's tenant; a hit in another tenant is
// audited as cross_tenant_refused and still reported as not found.
func (a *Admin) lookup(ctx context.Context, actor tenantctx.Actor, uid string) (store.User, error) {
	u, err := a.st.User(ctx, actor.TenantID, uid)
	if err == nil {
		return u, nil
	}
	if errors.Is(err, store.ErrNotFound) && tenantctx.ValidTenantID(uid) {
		if other, oerr := a.st.UserAnyTenant(ctx, uid); oerr == nil && other.TenantID != actor.TenantID {
			a.emit(audit.Event{Type: audit.CrossTenantRefused, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: "foreign_user",
				SubjectKind: "user", SubjectID: uid, Details: map[string]any{"target_tenant": other.TenantID}})
		}
	}
	return store.User{}, ErrNotFound
}

func (a *Admin) isLastOwner(ctx context.Context, tid, uid string) (bool, error) {
	roles, err := a.st.Roles(ctx, tid, uid)
	if err != nil {
		return false, err
	}
	owner := false
	for _, r := range roles {
		if r == "owner" {
			owner = true
		}
	}
	if !owner {
		return false, nil
	}
	n, err := a.st.CountWithRole(ctx, tid, "owner")
	if err != nil {
		return false, err
	}
	return n <= 1, nil
}

// Deactivate blocks sign-in and decisions and ends every session.
func (a *Admin) Deactivate(ctx context.Context, actor tenantctx.Actor, uid string) error {
	u, err := a.lookup(ctx, actor, uid)
	if err != nil {
		return err
	}
	if u.Status == "imported" {
		return ErrInvalidState
	}
	if last, err := a.isLastOwner(ctx, actor.TenantID, uid); err != nil {
		return err
	} else if last {
		a.emit(audit.Event{Type: audit.UserDeactivated, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: "last_owner", SubjectKind: "user", SubjectID: uid})
		return ErrLastOwner
	}
	if u.Status != "deactivated" {
		if err := a.st.UpdateUserStatus(ctx, actor.TenantID, uid, "deactivated"); err != nil {
			return err
		}
	}
	if err := a.sessions.RevokeUser(ctx, actor.TenantID, uid, session.ReasonDeactivated, ""); err != nil {
		return err
	}
	a.emit(audit.Event{Type: audit.UserDeactivated, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "user", SubjectID: uid})
	return nil
}

// Reactivate restores sign-in; sessions are not restored.
func (a *Admin) Reactivate(ctx context.Context, actor tenantctx.Actor, uid string) error {
	u, err := a.lookup(ctx, actor, uid)
	if err != nil {
		return err
	}
	if u.Status == "imported" {
		return ErrInvalidState
	}
	if u.Status != "deactivated" {
		return nil
	}
	if err := a.st.UpdateUserStatus(ctx, actor.TenantID, uid, "active"); err != nil {
		return err
	}
	a.emit(audit.Event{Type: audit.UserReactivated, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "user", SubjectID: uid})
	return nil
}

// RemoveImported hard-deletes a never-invited imported user; the directory
// link cascades and no e-mail is sent. Every other status is ErrInvalidState,
// so this is never a general user delete.
func (a *Admin) RemoveImported(ctx context.Context, actor tenantctx.Actor, uid string) error {
	u, err := a.lookup(ctx, actor, uid)
	if err != nil {
		return err
	}
	if u.Status != "imported" {
		return ErrInvalidState
	}
	if err := a.st.DeleteImportedUser(ctx, actor.TenantID, uid); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Invited or removed since the lookup: the delete is guarded by
			// status, so nothing else was touched.
			return ErrInvalidState
		}
		return err
	}
	a.emit(audit.Event{Type: audit.ImportedUserDeleted, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "user", SubjectID: uid})
	return nil
}

// ForceSignout ends every session of a user.
func (a *Admin) ForceSignout(ctx context.Context, actor tenantctx.Actor, uid string) error {
	if _, err := a.lookup(ctx, actor, uid); err != nil {
		return err
	}
	return a.sessions.RevokeUser(ctx, actor.TenantID, uid, session.ReasonAdmin, "")
}

func (a *Admin) emit(e audit.Event) {
	if a.audit != nil {
		_ = a.audit.Emit(e)
	}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
