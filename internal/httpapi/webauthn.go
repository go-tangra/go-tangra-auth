package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-auth/v4/internal/mfa"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra-auth/v4/internal/user"
	"github.com/go-tangra/go-tangra-auth/v4/internal/webauthn"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

// WebAuthnDeps are the security-key services (feature 018). Keys is nil when
// webauthn is disabled: the routes stay mounted (the contract declares them)
// and answer 404 webauthn_disabled.
type WebAuthnDeps struct {
	Keys   *webauthn.Service
	MFA    *mfa.Service
	Signin *user.Service
	Admin  *user.Admin
	RPID   string // shown so the console can name the address keys are bound to
}

// Security-key refusals. Failures of signed-in ceremonies are never 401: the
// console treats 401 as a lost session.
var (
	errWebAuthnDisabled   = &Error{http.StatusNotFound, "webauthn_disabled"}
	errInvalidKeyName     = &Error{http.StatusBadRequest, "invalid_name"}
	errKeyNameTaken       = &Error{http.StatusConflict, "name_taken"}
	errKeyLimit           = &Error{http.StatusConflict, "key_limit"}
	errAlreadyRegistered  = &Error{http.StatusConflict, "already_registered"}
	errRegistrationFailed = &Error{http.StatusBadRequest, "registration_failed"}
	errConfirmationFailed = &Error{http.StatusForbidden, "confirmation_failed"}
	errLastFactor         = &Error{http.StatusConflict, "last_factor_required"}
	errNoKeys             = &Error{http.StatusConflict, "no_keys"}
	errInvalidChallenge   = &Error{http.StatusUnauthorized, "invalid_challenge"}
	errMFAFailed          = &Error{http.StatusUnauthorized, "mfa_failed"}
	errKeyFlagged         = &Error{http.StatusUnauthorized, "key_flagged"}
)

func webauthnError(err error) error {
	switch {
	case errors.Is(err, webauthn.ErrInvalidName):
		return errInvalidKeyName
	case errors.Is(err, webauthn.ErrNameTaken):
		return errKeyNameTaken
	case errors.Is(err, webauthn.ErrKeyLimit):
		return errKeyLimit
	case errors.Is(err, webauthn.ErrAlreadyRegistered):
		return errAlreadyRegistered
	case errors.Is(err, webauthn.ErrRegistrationFailed):
		return errRegistrationFailed
	case errors.Is(err, webauthn.ErrConfirmationFailed):
		return errConfirmationFailed
	case errors.Is(err, webauthn.ErrLastFactor):
		return errLastFactor
	case errors.Is(err, webauthn.ErrNoKeys):
		return errNoKeys
	case errors.Is(err, webauthn.ErrLocked):
		return ErrLocked
	case errors.Is(err, user.ErrForbidden):
		return ErrForbidden
	}
	return adminError(err)
}

// RegisterWebAuthn mounts the security-key routes (contracts/http.md of 018).
func (s *Server) RegisterWebAuthn(d WebAuthnDeps) {
	s.MustHandle("POST", "/api/v1/signin/mfa/webauthn/options", s.signInKeyOptions(d))
	s.MustHandle("POST", "/api/v1/signin/mfa/webauthn", s.signInKey(d))
	s.MustHandle("GET", "/api/v1/me/mfa", s.myMFA(d))
	s.MustHandle("POST", "/api/v1/me/mfa/webauthn/register/options", s.keyRegisterOptions(d))
	s.MustHandle("POST", "/api/v1/me/mfa/webauthn/register", s.keyRegister(d))
	s.MustHandle("PATCH", "/api/v1/me/mfa/webauthn/{id}", s.keyRename(d))
	s.MustHandle("DELETE", "/api/v1/me/mfa/webauthn/{id}", s.keyRemove(d))
	s.MustHandle("POST", "/api/v1/me/mfa/stepup/options", s.keyStepUpOptions(d))
	s.MustHandle("GET", "/api/v1/admin/users/{id}/mfa", s.userMFA(d))
	s.MustHandle("POST", "/api/v1/admin/users/{id}/mfa/reset", s.userMFAReset(d))
}

type challengeBody struct {
	Challenge string `json:"challenge"`
}

func (s *Server) signInKeyOptions(d WebAuthnDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in challengeBody
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		opts, err := d.Signin.WebAuthnOptions(r.Context(), in.Challenge)
		if errors.Is(err, user.ErrInvalidCredentials) {
			err = errInvalidChallenge
		}
		if err != nil {
			Fail(w, r, s.rt.Logger(), signinError(err))
			return
		}
		WriteJSON(w, http.StatusOK, opts)
	}
}

func (s *Server) signInKey(d WebAuthnDeps) http.HandlerFunc {
	type body struct {
		Challenge  string          `json:"challenge"`
		Credential json.RawMessage `json:"credential"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		res, err := d.Signin.CompleteWebAuthn(r.Context(), in.Challenge, in.Credential, edge.ClientIP(r.Context()), r.UserAgent())
		switch {
		case errors.Is(err, user.ErrKeyFlagged):
			err = errKeyFlagged
		case errors.Is(err, user.ErrInvalidCredentials):
			err = errMFAFailed
		}
		if err != nil {
			Fail(w, r, s.rt.Logger(), signinError(err))
			return
		}
		s.finishSignin(w, res)
	}
}

func (s *Server) myMFA(d WebAuthnDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		st, err := d.MFA.State(r.Context(), a.TenantID, a.UserID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), webauthnError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"totp": st.TOTP, "keys": st.Keys, "recovery_codes_left": st.RecoveryCodesLeft, "required": st.Required,
			"webauthn": map[string]any{"enabled": d.Keys != nil, "rp_id": d.RPID}})
	}
}

// keyActor returns the signed-in user when security keys are enabled.
func keyActor(d WebAuthnDeps, r *http.Request) (tenantctx.Actor, error) {
	a, err := RequireUser(r)
	if err != nil {
		return tenantctx.Actor{}, err
	}
	if d.Keys == nil {
		return tenantctx.Actor{}, errWebAuthnDisabled
	}
	return a, nil
}

func (s *Server) keyRegisterOptions(d WebAuthnDeps) http.HandlerFunc {
	type body struct {
		Name string `json:"name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := keyActor(d, r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		opts, err := d.Keys.BeginRegistration(r.Context(), a, in.Name)
		if err != nil {
			Fail(w, r, s.rt.Logger(), webauthnError(err))
			return
		}
		WriteJSON(w, http.StatusOK, opts)
	}
}

type credentialBody struct {
	Credential json.RawMessage `json:"credential"`
}

func (s *Server) keyRegister(d WebAuthnDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := keyActor(d, r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in credentialBody
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		reg, err := d.Keys.FinishRegistration(r.Context(), a, in.Credential)
		if err != nil {
			Fail(w, r, s.rt.Logger(), webauthnError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, reg)
	}
}

func (s *Server) keyRename(d WebAuthnDeps) http.HandlerFunc {
	type body struct {
		Name string `json:"name"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := keyActor(d, r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		k, err := d.Keys.Rename(r.Context(), a, r.PathValue("id"), in.Name)
		if err != nil {
			Fail(w, r, s.rt.Logger(), webauthnError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"key": k})
	}
}

func (s *Server) keyRemove(d WebAuthnDeps) http.HandlerFunc {
	type body struct {
		Code       string          `json:"code"`
		Credential json.RawMessage `json:"credential"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := keyActor(d, r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Keys.Remove(r.Context(), a, r.PathValue("id"), webauthn.Confirmation{Code: in.Code, Credential: in.Credential}); err != nil {
			Fail(w, r, s.rt.Logger(), webauthnError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) keyStepUpOptions(d WebAuthnDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := keyActor(d, r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		opts, err := d.Keys.StepUpOptions(r.Context(), a)
		if err != nil {
			Fail(w, r, s.rt.Logger(), webauthnError(err))
			return
		}
		WriteJSON(w, http.StatusOK, opts)
	}
}

// adminKey is a key as an administrator sees it: no id, no key material.
type adminKey struct {
	Name       string  `json:"name"`
	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
	Flagged    bool    `json:"flagged"`
}

func (s *Server) userMFA(d WebAuthnDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		u, err := d.Admin.Lookup(r.Context(), a, r.PathValue("id"))
		if err != nil {
			Fail(w, r, nil, adminError(err))
			return
		}
		st, err := d.MFA.State(r.Context(), a.TenantID, u.ID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), adminError(err))
			return
		}
		keys := make([]adminKey, 0, len(st.Keys))
		for _, k := range st.Keys {
			v := adminKey{Name: k.Name, CreatedAt: k.CreatedAt.UTC().Format(timeLayout), Flagged: k.Flagged}
			if k.LastUsedAt != nil {
				t := k.LastUsedAt.UTC().Format(timeLayout)
				v.LastUsedAt = &t
			}
			keys = append(keys, v)
		}
		WriteJSON(w, http.StatusOK, map[string]any{"totp": st.TOTP, "keys": keys, "recovery_codes_left": st.RecoveryCodesLeft, "required": st.Required})
	}
}

const timeLayout = "2006-01-02T15:04:05Z07:00"

func (s *Server) userMFAReset(d WebAuthnDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Admin.ResetMFA(r.Context(), a, r.PathValue("id")); err != nil {
			Fail(w, r, s.rt.Logger(), webauthnError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
