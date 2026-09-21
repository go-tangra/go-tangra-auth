package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/invite"
	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
	"github.com/go-freya/freya/services/auth/internal/user"
	"github.com/go-freya/freya/transport/edge"
)

// US2Deps are the administration services.
type US2Deps struct {
	Invites  *invite.Service
	Admin    *user.Admin
	Assigner *authz.Assigner
	Audit    audit.Querier
	Sessions *session.Manager
}

// Admin refusals (closed vocabulary from the OpenAPI document).
var (
	errLastOwner      = &Error{http.StatusForbidden, "last_owner"}
	errSelfEscalation = &Error{http.StatusForbidden, "self_escalation"}
	errInvalidToken   = &Error{http.StatusBadRequest, "invalid_token"}
	errPasswordPolicy = &Error{http.StatusBadRequest, "password_policy"}
)

func adminError(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, user.ErrLastOwner), errors.Is(err, authz.ErrLastOwner):
		return errLastOwner
	case errors.Is(err, authz.ErrSelfEscalation):
		return errSelfEscalation
	case errors.Is(err, invite.ErrInvalidToken):
		return errInvalidToken
	case errors.Is(err, invite.ErrPolicy):
		return errPasswordPolicy
	case errors.Is(err, invite.ErrBadEmail), errors.Is(err, audit.ErrFilter):
		return ErrValidation
	case errors.Is(err, tenantctx.ErrNoActor), errors.Is(err, tenantctx.ErrCrossTenant), errors.Is(err, tenantctx.ErrNoOperatorGrant):
		return ErrForbidden
	}
	return err
}

// RequireAdmin returns the actor when they administer their tenant (owner or
// admin role). Operators reach a customer tenant only through a grant
// (see Server.adminScope), which rewrites the request context.
func RequireAdmin(r *http.Request) (tenantctx.Actor, error) {
	a, err := RequireUser(r)
	if err != nil {
		return tenantctx.Actor{}, err
	}
	for _, role := range a.Roles {
		if role == "owner" || role == "admin" {
			return a, nil
		}
	}
	return tenantctx.Actor{}, ErrForbidden
}

// RegisterUS2 mounts the administration routes.
func (s *Server) RegisterUS2(d US2Deps) {
	s.MustHandle("GET", "/api/v1/admin/users", s.listUsers(d))
	s.MustHandle("PUT", "/api/v1/admin/users/{id}/roles", s.setUserRoles(d))
	s.MustHandle("POST", "/api/v1/admin/users/{id}/deactivate", s.userStatus(d, "deactivate"))
	s.MustHandle("POST", "/api/v1/admin/users/{id}/reactivate", s.userStatus(d, "reactivate"))
	s.MustHandle("POST", "/api/v1/admin/users/{id}/sessions/revoke", s.userStatus(d, "signout"))
	s.MustHandle("POST", "/api/v1/admin/invitations", s.createInvitation(d))
	s.MustHandle("POST", "/api/v1/admin/invitations/{id}/resend", s.resendInvitation(d))
	s.MustHandle("POST", "/api/v1/invitations/accept", s.acceptInvitation(d))
	s.MustHandle("GET", "/api/v1/admin/audit", s.queryAudit(d))
}

func (s *Server) listUsers(d US2Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		users, err := d.Admin.List(r.Context(), a, r.URL.Query().Get("q"), r.URL.Query().Get("status"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), adminError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": users})
	}
}

func (s *Server) setUserRoles(d US2Deps) http.HandlerFunc {
	type body struct {
		RoleIDs []string `json:"role_ids"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		uid := r.PathValue("id")
		if _, err := d.Admin.Lookup(r.Context(), a, uid); err != nil {
			Fail(w, r, nil, adminError(err))
			return
		}
		slugs, err := d.Assigner.AssignRoles(r.Context(), a.TenantID, uid, in.RoleIDs)
		if err != nil {
			Fail(w, r, s.rt.Logger(), adminError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"roles": slugs})
	}
}

func (s *Server) userStatus(d US2Deps, op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		uid := r.PathValue("id")
		switch op {
		case "deactivate":
			err = d.Admin.Deactivate(r.Context(), a, uid)
		case "reactivate":
			err = d.Admin.Reactivate(r.Context(), a, uid)
		default:
			err = d.Admin.ForceSignout(r.Context(), a, uid)
		}
		if err != nil {
			Fail(w, r, s.rt.Logger(), adminError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) createInvitation(d US2Deps) http.HandlerFunc {
	type body struct {
		Email     string   `json:"email"`
		RoleIDs   []string `json:"role_ids"`
		GroupIDs  []string `json:"group_ids"`
		FirstName string   `json:"first_name"`
		LastName  string   `json:"last_name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		if _, err := d.Invites.CreateWith(r.Context(), a, a.TenantID, invite.Params{Email: in.Email, RoleIDs: in.RoleIDs, GroupIDs: in.GroupIDs, FirstName: in.FirstName, LastName: in.LastName}); err != nil {
			Fail(w, r, s.rt.Logger(), adminError(err))
			return
		}
		// Identical body whether or not the address already has an account.
		WriteJSON(w, http.StatusAccepted, map[string]any{"queued": true})
	}
}

func (s *Server) resendInvitation(d US2Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Invites.Resend(r.Context(), a, a.TenantID, r.PathValue("id")); err != nil {
			Fail(w, r, s.rt.Logger(), adminError(err))
			return
		}
		WriteJSON(w, http.StatusAccepted, map[string]any{"queued": true})
	}
}

func (s *Server) acceptInvitation(d US2Deps) http.HandlerFunc {
	type body struct {
		Token       string `json:"token"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		acc, err := d.Invites.Accept(r.Context(), in.Token, in.DisplayName, in.Password)
		if err != nil {
			Fail(w, r, s.rt.Logger(), adminError(err))
			return
		}
		sess, secret, err := d.Sessions.Create(r.Context(), session.CreateParams{TenantID: acc.Tenant.ID, UserID: acc.User.ID, Roles: acc.Roles, AMR: []string{"pwd"},
			Operator: acc.Operator, IPHash: user.HashIP(edge.ClientIP(r.Context())), UserAgent: r.UserAgent(), Policy: acc.Policy})
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		SetSessionCookie(w, secret, int(sess.ExpiresAt.Sub(sess.CreatedAt).Seconds()))
		edge.IssueCSRFCookie(w)
		WriteJSON(w, http.StatusOK, map[string]any{"signed_in": true, "session_id": sess.ID, "roles": acc.Roles, "mfa_setup_required": acc.Policy.MFARequired})
	}
}

func (s *Server) queryAudit(d US2Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if !hasAny(a.Roles, "owner", "admin", "auditor") {
			Fail(w, r, nil, ErrForbidden)
			return
		}
		q := r.URL.Query()
		f := audit.Filter{UserID: q.Get("user_id"), EventType: q.Get("event_type"), Cursor: q.Get("cursor")}
		for _, p := range []struct {
			key string
			dst *time.Time
		}{{"from", &f.From}, {"to", &f.To}} {
			if v := q.Get(p.key); v != "" {
				ts, err := time.Parse(time.RFC3339, v)
				if err != nil {
					Fail(w, r, nil, ErrValidation)
					return
				}
				*p.dst = ts
			}
		}
		page, err := audit.Query(r.Context(), d.Audit, a.TenantID, f)
		if err != nil {
			Fail(w, r, s.rt.Logger(), adminError(err))
			return
		}
		WriteJSON(w, http.StatusOK, page)
	}
}

func hasAny(roles []string, want ...string) bool {
	for _, r := range roles {
		for _, w := range want {
			if r == w {
				return true
			}
		}
	}
	return false
}
