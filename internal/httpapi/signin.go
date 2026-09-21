package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenant"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
	"github.com/go-freya/freya/services/auth/internal/token"
	"github.com/go-freya/freya/services/auth/internal/user"
	"github.com/go-freya/freya/transport/edge"
)

// TenantResolver looks up a tenant for the pre-sign-in screen.
type TenantResolver interface {
	TenantBySlug(ctx context.Context, slug string) (store.Tenant, error)
}

// US1Deps are the sign-in, session and token services.
type US1Deps struct {
	Signin   *user.Service
	Sessions *session.Manager
	Tokens   *token.Issuer
	Ring     *token.Ring
	Tenants  TenantResolver
	Profiles ProfileSource // optional: enriches GET /api/v1/session
}

// Profile is what the console shows about the signed-in user.
type Profile struct {
	Email, DisplayName     string
	FirstName, LastName    string
	AvatarURL              string
	MFAEnabled             bool
	MFARequired            bool // tenant policy
	TenantSlug, TenantName string
}

// ProfileSource loads a Profile.
type ProfileSource interface {
	Profile(ctx context.Context, tenantID, userID string) (Profile, error)
}

// Refusals shared by the sign-in handlers.
var (
	ErrInvalidCredentials = &Error{http.StatusUnauthorized, "invalid_credentials"}
	ErrLocked             = &Error{http.StatusLocked, "locked"}
	ErrRateLimited        = &Error{http.StatusTooManyRequests, "rate_limited"}
)

func signinError(err error) error {
	switch {
	case errors.Is(err, user.ErrInvalidCredentials):
		return ErrInvalidCredentials
	case errors.Is(err, user.ErrLocked):
		return ErrLocked
	case errors.Is(err, user.ErrRateLimited):
		return ErrRateLimited
	}
	return err
}

// RegisterUS1 mounts sign-in, session, token and JWKS routes.
func (s *Server) RegisterUS1(d US1Deps) {
	s.MustHandle("GET", "/api/v1/tenants/resolve", s.resolveTenant(d))
	s.MustHandle("POST", "/api/v1/signin", s.signIn(d))
	s.MustHandle("POST", "/api/v1/signin/mfa", s.signInMFA(d))
	s.MustHandle("POST", "/api/v1/signout", s.signOut(d))
	s.MustHandle("GET", "/api/v1/session", s.getSession(d))
	s.MustHandle("POST", "/api/v1/session/token", s.issueToken(d))
	s.MustHandle("GET", "/api/v1/sessions", s.listSessions(d))
	s.MustHandle("POST", "/api/v1/sessions/{id}/revoke", s.revokeSession(d))
	s.MustHandle("GET", "/.well-known/jwks.json", s.jwks(d))
}

func (s *Server) resolveTenant(d US1Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug, err := tenant.ParseSlug(r.URL.Query().Get("slug"))
		if err != nil {
			WriteError(w, http.StatusNotFound, ErrNotFound.Reason)
			return
		}
		t, err := d.Tenants.TenantBySlug(r.Context(), slug)
		if err != nil || t.Status != "active" {
			WriteError(w, http.StatusNotFound, ErrNotFound.Reason)
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"slug": t.Slug, "display_name": t.DisplayName})
	}
}

func (s *Server) signIn(d US1Deps) http.HandlerFunc {
	type body struct {
		Tenant   string `json:"tenant"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		res, err := d.Signin.Start(r.Context(), user.Input{TenantSlug: in.Tenant, Email: in.Email, Password: in.Password, IP: edge.ClientIP(r.Context()), UserAgent: r.UserAgent()})
		if err != nil {
			Fail(w, r, s.rt.Logger(), signinError(err))
			return
		}
		s.finishSignin(w, res)
	}
}

func (s *Server) signInMFA(d US1Deps) http.HandlerFunc {
	type body struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		res, err := d.Signin.CompleteMFA(r.Context(), in.Challenge, in.Code, edge.ClientIP(r.Context()), r.UserAgent())
		if err != nil {
			Fail(w, r, s.rt.Logger(), signinError(err))
			return
		}
		s.finishSignin(w, res)
	}
}

// finishSignin sets the cookies for a completed sign-in or returns the MFA
// challenge; bodies never carry anything that distinguishes failure causes.
func (s *Server) finishSignin(w http.ResponseWriter, res user.Result) {
	if res.MFARequired {
		WriteJSON(w, http.StatusOK, map[string]any{"mfa_required": true, "challenge": res.Challenge})
		return
	}
	maxAge := int(res.Session.ExpiresAt.Sub(res.Session.CreatedAt).Seconds())
	SetSessionCookie(w, res.Secret, maxAge)
	edge.IssueCSRFCookie(w)
	WriteJSON(w, http.StatusOK, map[string]any{"signed_in": true, "session_id": res.Session.ID, "roles": res.Roles, "mfa_setup_required": res.MFASetupRequired})
}

func (s *Server) signOut(d US1Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			ClearSessionCookie(w)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := d.Sessions.Revoke(r.Context(), a.TenantID, a.SessionID, session.ReasonSignout); err != nil && !errors.Is(err, store.ErrNotFound) {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		ClearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) getSession(d US1Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The CSRF cookie is issued here (even to anonymous callers) so the
		// console can sign in; it is random and not bound to a session.
		if _, err := r.Cookie(edge.CSRFCookie); err != nil {
			edge.IssueCSRFCookie(w)
		}
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		WriteJSON(w, http.StatusOK, sessionInfo(r.Context(), d, a))
	}
}

// SessionInfo is the GET /api/v1/session body.
type SessionInfo struct {
	SessionID string         `json:"session_id"`
	User      map[string]any `json:"user"`
	Tenant    map[string]any `json:"tenant"`
	Roles     []string       `json:"roles"`
	Operator  bool           `json:"operator"`
	// MFASetupRequired asks the console to enrol before anything else.
	MFASetupRequired bool `json:"mfa_setup_required"`
}

func sessionInfo(ctx context.Context, d US1Deps, a tenantctx.Actor) SessionInfo {
	info := SessionInfo{SessionID: a.SessionID, User: map[string]any{"id": a.UserID, "display_name": a.DisplayName, "avatar_url": a.AvatarURL}, Tenant: map[string]any{"id": a.TenantID}, Roles: nonNil(a.Roles), Operator: a.Kind == tenantctx.KindOperator}
	if d.Profiles != nil {
		if p, err := d.Profiles.Profile(ctx, a.TenantID, a.UserID); err == nil {
			// Never the phone: the session document is shared with the platform.
			info.User = map[string]any{"id": a.UserID, "email": p.Email, "display_name": p.DisplayName, "mfa_enabled": p.MFAEnabled,
				"first_name": p.FirstName, "last_name": p.LastName, "avatar_url": p.AvatarURL}
			info.Tenant = map[string]any{"id": a.TenantID, "slug": p.TenantSlug, "display_name": p.TenantName}
			info.MFASetupRequired = p.MFARequired && !p.MFAEnabled
		}
	}
	return info
}

func (s *Server) issueToken(d US1Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		tok, c, err := d.Tokens.Issue(token.Request{UserID: a.UserID, TenantID: a.TenantID, SessionID: a.SessionID, Roles: a.Roles, AMR: amrOf(a)})
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": int(c.ExpiresAt.Sub(c.IssuedAt.Time).Seconds())})
	}
}

func amrOf(a tenantctx.Actor) []string {
	if a.AMR != nil {
		return a.AMR
	}
	return []string{"pwd"}
}

func (s *Server) listSessions(d US1Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		views, err := d.Sessions.ListMine(r.Context(), a.TenantID, a.UserID, a.SessionID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		WriteJSON(w, http.StatusOK, views)
	}
}

func (s *Server) revokeSession(d US1Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		id := r.PathValue("id")
		// Only the owner's sessions are listed, so a foreign id is simply not found.
		mine, err := d.Sessions.ListMine(r.Context(), a.TenantID, a.UserID, a.SessionID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		owned := false
		for _, v := range mine {
			if v.ID == id {
				owned = true
			}
		}
		if !owned {
			Fail(w, r, nil, ErrNotFound)
			return
		}
		if err := d.Sessions.Revoke(r.Context(), a.TenantID, id, session.ReasonUserRevoked); err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		if id == a.SessionID {
			ClearSessionCookie(w)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) jwks(d US1Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(d.Ring.JWKSJSON())
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
