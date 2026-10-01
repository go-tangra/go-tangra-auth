package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
)

// policyRefusal is password_policy naming the violated rule (one of the
// password.Requirements keys) in detail.rule. The submitted password is
// never echoed.
type policyRefusal struct{ rule string }

func (p *policyRefusal) Error() string { return errPasswordPolicy.Reason }

// passwordPolicy maps a policy failure to its refusal; a failure without a
// known rule stays the bare password_policy reason.
func passwordPolicy(err error) error {
	if rule := password.Rule(err); rule != "" {
		return &policyRefusal{rule: rule}
	}
	return errPasswordPolicy
}

// writePolicyRefusal writes err when it is a policyRefusal.
func writePolicyRefusal(w http.ResponseWriter, err error) bool {
	var p *policyRefusal
	if !errors.As(err, &p) {
		return false
	}
	WriteDetail(w, errPasswordPolicy, map[string]any{"rule": p.rule})
	return true
}

type tokenBody struct {
	Token string `json:"token"`
}

// invitationPasswordPolicy publishes the rules a redeemable invitation's
// password must meet (the page shows them before the user types). The token
// travels in the body, never the URL; only policy parameters are returned.
func (s *Server) invitationPasswordPolicy(d US2Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in tokenBody
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		req, err := d.Invites.Requirements(r.Context(), in.Token)
		if err != nil {
			Fail(w, r, s.rt.Logger(), adminError(err))
			return
		}
		WriteJSON(w, http.StatusOK, req)
	}
}

// recoveryPasswordPolicy is invitationPasswordPolicy for a reset link.
func (s *Server) recoveryPasswordPolicy(d US4Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in tokenBody
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		req, err := d.Recovery.Requirements(r.Context(), in.Token)
		if err != nil {
			Fail(w, r, s.rt.Logger(), accountError(err))
			return
		}
		WriteJSON(w, http.StatusOK, req)
	}
}

// myPasswordPolicy returns the rules of the signed-in user's tenant.
func (s *Server) myPasswordPolicy(d US4Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		req, err := d.Changer.Requirements(r.Context(), a)
		if err != nil {
			Fail(w, r, s.rt.Logger(), accountError(err))
			return
		}
		WriteJSON(w, http.StatusOK, req)
	}
}
