package httpapi

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/go-tangra/go-tangra-auth/v4/internal/oauth"
)

// OAuthDeps wires the authorization-code flow.
type OAuthDeps struct{ OAuth *oauth.Service }

var (
	errInvalidRequest = &Error{http.StatusBadRequest, "invalid_request"}
	errInvalidGrant   = &Error{http.StatusBadRequest, "invalid_grant"}
	errInvalidClient  = &Error{http.StatusUnauthorized, "invalid_client"}
)

func oauthError(err error) error {
	switch {
	case errors.Is(err, oauth.ErrInvalidRequest):
		return errInvalidRequest
	case errors.Is(err, oauth.ErrInvalidGrant):
		return errInvalidGrant
	case errors.Is(err, oauth.ErrInvalidClient):
		return errInvalidClient
	}
	return err
}

// RegisterOAuth mounts /authorize and /api/v1/oauth/token.
func (s *Server) RegisterOAuth(d OAuthDeps) {
	s.MustHandle("GET", "/authorize", s.authorize(d))
	s.MustHandle("POST", "/api/v1/oauth/token", s.oauthToken(d))
}

func (s *Server) authorize(d OAuthDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := oauth.ParseAuthorize(r.URL.Query())
		if err != nil {
			Fail(w, r, nil, oauthError(err))
			return
		}
		client, err := d.OAuth.ValidateClient(r.Context(), req)
		if err != nil {
			// Never redirect to an unregistered URI.
			Fail(w, r, nil, oauthError(err))
			return
		}
		a, err := RequireUser(r)
		if err != nil {
			// Bounce through the console sign-in and come back here.
			next := url.Values{"next": {r.URL.RequestURI()}}
			http.Redirect(w, r, ConsolePrefix+"/signin?"+next.Encode(), http.StatusFound)
			return
		}
		code, err := d.OAuth.IssueCode(r.Context(), a, client, req)
		if err != nil {
			Fail(w, r, s.rt.Logger(), oauthError(err))
			return
		}
		target, _ := url.Parse(req.RedirectURI)
		q := target.Query()
		q.Set("code", code)
		q.Set("state", req.State)
		target.RawQuery = q.Encode()
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target.String(), http.StatusFound)
	}
}

func (s *Server) oauthToken(d OAuthDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			Fail(w, r, nil, errInvalidRequest)
			return
		}
		f := r.PostForm
		resp, err := d.OAuth.Redeem(r.Context(), oauth.TokenRequest{GrantType: f.Get("grant_type"), Code: f.Get("code"), RedirectURI: f.Get("redirect_uri"),
			ClientID: f.Get("client_id"), CodeVerifier: f.Get("code_verifier"), ClientSecret: f.Get("client_secret")})
		if err != nil {
			Fail(w, r, s.rt.Logger(), oauthError(err))
			return
		}
		w.Header().Set("Pragma", "no-cache")
		WriteJSON(w, http.StatusOK, resp)
	}
}
