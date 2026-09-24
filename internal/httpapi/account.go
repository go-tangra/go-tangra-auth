package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-auth/v4/internal/mfa"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
	"github.com/go-tangra/go-tangra-auth/v4/internal/user"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

// US4Deps are the self-service account services.
type US4Deps struct {
	MFA      *mfa.Service
	Changer  *password.Changer
	Recovery *password.Recovery
}

var (
	errInvalidCode = &Error{http.StatusUnauthorized, "invalid_code"}
	errMFARequired = &Error{http.StatusForbidden, "mfa_required"}
	errNotEnrolled = &Error{http.StatusConflict, "not_enrolled"}
	errNoPending   = &Error{http.StatusConflict, "no_pending_enrolment"}
)

func accountError(err error) error {
	switch {
	case errors.Is(err, password.ErrCurrent):
		return ErrInvalidCredentials
	case errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong), errors.Is(err, password.ErrWeak):
		return errPasswordPolicy
	case errors.Is(err, password.ErrInvalidToken):
		return errInvalidToken
	case errors.Is(err, mfa.ErrInvalidCode):
		return errInvalidCode
	case errors.Is(err, mfa.ErrRequired):
		return errMFARequired
	case errors.Is(err, mfa.ErrNotEnrolled):
		return errNotEnrolled
	case errors.Is(err, mfa.ErrNoPending):
		return errNoPending
	}
	return adminError(err)
}

// RegisterUS4 mounts account security and recovery routes.
func (s *Server) RegisterUS4(d US4Deps) {
	s.MustHandle("POST", "/api/v1/me/password", s.changePassword(d))
	s.MustHandle("POST", "/api/v1/me/mfa/enroll", s.mfaEnrol(d))
	s.MustHandle("POST", "/api/v1/me/mfa/confirm", s.mfaConfirm(d))
	s.MustHandle("POST", "/api/v1/me/mfa/disable", s.mfaDisable(d))
	s.MustHandle("POST", "/api/v1/me/mfa/recovery-codes", s.mfaRecoveryCodes(d))
	s.MustHandle("POST", "/api/v1/recovery", s.recoveryRequest(d))
	s.MustHandle("POST", "/api/v1/recovery/complete", s.recoveryComplete(d))
}

func (s *Server) changePassword(d US4Deps) http.HandlerFunc {
	type body struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Changer.Change(r.Context(), a, in.Current, in.New); err != nil {
			Fail(w, r, s.rt.Logger(), accountError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) mfaEnrol(d US4Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		enr, err := d.MFA.Enrol(r.Context(), a)
		if err != nil {
			Fail(w, r, s.rt.Logger(), accountError(err))
			return
		}
		WriteJSON(w, http.StatusOK, enr)
	}
}

type codeBody struct {
	Code string `json:"code"`
}

func (s *Server) mfaConfirm(d US4Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in codeBody
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		codes, err := d.MFA.Confirm(r.Context(), a, in.Code)
		if err != nil {
			Fail(w, r, s.rt.Logger(), accountError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
	}
}

func (s *Server) mfaDisable(d US4Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in codeBody
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.MFA.Disable(r.Context(), a, in.Code); err != nil {
			Fail(w, r, s.rt.Logger(), accountError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) mfaRecoveryCodes(d US4Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in codeBody
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		codes, err := d.MFA.Regenerate(r.Context(), a, in.Code)
		if err != nil {
			Fail(w, r, s.rt.Logger(), accountError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
	}
}

func (s *Server) recoveryRequest(d US4Deps) http.HandlerFunc {
	type body struct {
		Tenant string `json:"tenant"`
		Email  string `json:"email"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		_ = d.Recovery.Request(r.Context(), in.Tenant, in.Email, user.HashIP(edge.ClientIP(r.Context())))
		WriteJSON(w, http.StatusAccepted, map[string]any{"queued": true})
	}
}

func (s *Server) recoveryComplete(d US4Deps) http.HandlerFunc {
	type body struct {
		Token    string `json:"token"`
		Password string `json:"new_password"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Recovery.Complete(r.Context(), in.Token, in.Password); err != nil {
			Fail(w, r, s.rt.Logger(), accountError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
