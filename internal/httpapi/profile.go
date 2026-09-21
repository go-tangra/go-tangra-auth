package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
	"github.com/go-freya/freya/services/auth/internal/user"
)

// IdentityRefreshHeader tells the gateway that the caller's identity attributes
// changed and its cached identity for this cookie must be dropped. The gateway
// strips it before the browser sees it.
const IdentityRefreshHeader = "X-Freya-Identity-Refresh"

// ProfileDeps wires the profile, avatar and lookup routes (feature 004).
type ProfileDeps struct {
	Profiles            *user.Profiles
	Avatars             *user.Avatars
	Sessions            *session.Manager
	Cache               *cache.Cache
	LookupRatePerMinute int
	MaxAvatarBytes      int64
}

// Profile refusals (closed vocabulary from the OpenAPI document).
var (
	errInvalidPhone        = &Error{http.StatusBadRequest, "invalid_phone"}
	errUnsupportedType     = &Error{http.StatusBadRequest, "unsupported_type"}
	errTooLargeDimensions  = &Error{http.StatusBadRequest, "too_large_dimensions"}
	errDecodeFailed        = &Error{http.StatusBadRequest, "decode_failed"}
	errBodyTooLarge        = &Error{http.StatusRequestEntityTooLarge, "body_too_large"}
	errLookupRateLimited   = &Error{http.StatusTooManyRequests, "rate_limited"}
	errProfileNotAvailable = &Error{http.StatusServiceUnavailable, "temporarily_unavailable"}
)

func profileError(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, tenantctx.ErrCrossTenant):
		return ErrNotFound
	case errors.Is(err, user.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, user.ErrInvalidName), errors.Is(err, user.ErrQueryTooShort):
		return ErrValidation
	case errors.Is(err, user.ErrInvalidPhone):
		return errInvalidPhone
	case errors.Is(err, user.ErrUnsupportedType):
		return errUnsupportedType
	case errors.Is(err, user.ErrTooLargeDimensions):
		return errTooLargeDimensions
	case errors.Is(err, user.ErrDecodeFailed):
		return errDecodeFailed
	case errors.Is(err, user.ErrTooLarge):
		return errBodyTooLarge
	}
	return err
}

// RegisterProfiles mounts the self-service, admin and lookup profile routes.
func (s *Server) RegisterProfiles(d ProfileDeps) {
	s.MustHandle("GET", "/api/v1/me/profile", s.getProfile(d, false))
	s.MustHandle("PUT", "/api/v1/me/profile", s.updateProfile(d, false))
	s.MustHandle("PUT", "/api/v1/me/avatar", s.uploadAvatar(d))
	s.MustHandle("DELETE", "/api/v1/me/avatar", s.removeAvatar(d, false))
	s.MustHandle("GET", "/api/v1/users/{id}/avatar/{avatar_id}", s.getAvatar(d))
	s.MustHandle("GET", "/api/v1/users/{id}", s.lookupUser(d))
	s.MustHandle("POST", "/api/v1/users/lookup", s.lookupUsers(d))
	s.MustHandle("GET", "/api/v1/users", s.searchUsers(d))
	s.MustHandle("GET", "/api/v1/admin/users/{id}/profile", s.getProfile(d, true))
	s.MustHandle("PUT", "/api/v1/admin/users/{id}/profile", s.updateProfile(d, true))
	s.MustHandle("DELETE", "/api/v1/admin/users/{id}/avatar", s.removeAvatar(d, true))
}

// target resolves the subject: the caller for self-service routes, the path id
// for admin routes (which require the admin role).
func target(r *http.Request, admin bool) (tenantctx.Actor, string, error) {
	if admin {
		a, err := RequireAdmin(r)
		return a, r.PathValue("id"), err
	}
	a, err := RequireUser(r)
	return a, a.UserID, err
}

// afterSelfChange evicts the subject's cached sessions and, for the caller's
// own profile, asks the gateway to drop its cached identity.
func afterChange(w http.ResponseWriter, r *http.Request, d ProfileDeps, actor tenantctx.Actor, uid string) {
	if d.Sessions != nil {
		d.Sessions.RefreshUser(r.Context(), actor.TenantID, uid)
	}
	if actor.UserID == uid {
		w.Header().Set(IdentityRefreshHeader, "1")
	}
}

func (s *Server) getProfile(d ProfileDeps, admin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, uid, err := target(r, admin)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		v, err := d.Profiles.Get(r.Context(), a, uid)
		if err != nil {
			Fail(w, r, s.rt.Logger(), profileError(err))
			return
		}
		WriteJSON(w, http.StatusOK, v)
	}
}

func (s *Server) updateProfile(d ProfileDeps, admin bool) http.HandlerFunc {
	type body struct {
		FirstName   string  `json:"first_name"`
		LastName    string  `json:"last_name"`
		Phone       string  `json:"phone"`
		DisplayName *string `json:"display_name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		a, uid, err := target(r, admin)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		v, err := d.Profiles.Update(r.Context(), a, uid, user.ProfileUpdate{FirstName: in.FirstName, LastName: in.LastName, Phone: in.Phone, DisplayName: in.DisplayName})
		if err != nil {
			Fail(w, r, s.rt.Logger(), profileError(err))
			return
		}
		afterChange(w, r, d, a, uid)
		WriteJSON(w, http.StatusOK, v)
	}
}

func (s *Server) uploadAvatar(d ProfileDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if d.Avatars == nil {
			Fail(w, r, nil, errProfileNotAvailable)
			return
		}
		// The service enforces MaxAvatarBytes itself; the edge limit is the outer wall.
		url, err := d.Avatars.Set(r.Context(), a, a.UserID, r.Body)
		if err != nil {
			Fail(w, r, s.rt.Logger(), profileError(err))
			return
		}
		afterChange(w, r, d, a, a.UserID)
		WriteJSON(w, http.StatusOK, map[string]string{"avatar_url": url})
	}
}

func (s *Server) removeAvatar(d ProfileDeps, admin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, uid, err := target(r, admin)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Avatars.Remove(r.Context(), a, uid); err != nil {
			Fail(w, r, s.rt.Logger(), profileError(err))
			return
		}
		afterChange(w, r, d, a, uid)
		w.WriteHeader(http.StatusNoContent)
	}
}

// getAvatar serves the bytes to any signed-in member of the tenant. Every
// refusal is a uniform 404 so nothing can be learned about other tenants.
func (s *Server) getAvatar(d ProfileDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, ErrNotFound)
			return
		}
		av, err := d.Avatars.Get(r.Context(), a, r.PathValue("id"), r.PathValue("avatar_id"))
		if err != nil {
			Fail(w, r, nil, ErrNotFound)
			return
		}
		h := w.Header()
		h.Set("Content-Type", user.AvatarContentType)
		h.Set("Content-Length", strconv.Itoa(len(av.Bytes)))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Disposition", `inline; filename="avatar.jpg"`)
		h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
		h.Set("Cache-Control", "private, max-age=31536000, immutable")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(av.Bytes)
		}
	}
}

// lookupLimited applies the per-user lookup rate (uniform for single and batch).
func (s *Server) lookupLimited(r *http.Request, d ProfileDeps, a tenantctx.Actor) bool {
	if d.Cache == nil || d.LookupRatePerMinute <= 0 {
		return false
	}
	n, err := d.Cache.Count(r.Context(), cache.RateKey("lookup", a.TenantID+":"+a.UserID), time.Minute)
	return err == nil && n > int64(d.LookupRatePerMinute)
}

func (s *Server) lookupUser(d ProfileDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if s.lookupLimited(r, d, a) {
			Fail(w, r, nil, errLookupRateLimited)
			return
		}
		out, err := d.Profiles.Lookup(r.Context(), a, []string{r.PathValue("id")})
		if err != nil {
			Fail(w, r, s.rt.Logger(), profileError(err))
			return
		}
		if len(out) != 1 {
			Fail(w, r, nil, ErrNotFound)
			return
		}
		WriteJSON(w, http.StatusOK, out[0])
	}
}

func (s *Server) lookupUsers(d ProfileDeps) http.HandlerFunc {
	type body struct {
		IDs []string `json:"ids"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if s.lookupLimited(r, d, a) {
			Fail(w, r, nil, errLookupRateLimited)
			return
		}
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		out, err := d.Profiles.Lookup(r.Context(), a, in.IDs)
		if err != nil {
			Fail(w, r, s.rt.Logger(), profileError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

// searchUsers is the subject picker: active members matching q, rate-limited
// like lookups, never phone.
func (s *Server) searchUsers(d ProfileDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if s.lookupLimited(r, d, a) {
			Fail(w, r, nil, errLookupRateLimited)
			return
		}
		out, err := d.Profiles.Search(r.Context(), a, r.URL.Query().Get("q"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), profileError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}
