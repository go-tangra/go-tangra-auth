package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// SessionCookie carries the opaque session secret (host-only, secure).
const SessionCookie = "__Host-session"

// SessionResolver turns a session cookie into an actor (implemented by the
// session package). Returning an error means "no session".
type SessionResolver interface {
	Resolve(ctx context.Context, secret string) (tenantctx.Actor, error)
}

// validate checks the request against the OpenAPI document for declared routes.
func (s *Server) validate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, params, err := s.router.FindRoute(r)
		if err != nil {
			if errors.Is(err, routers.ErrPathNotFound) {
				next.ServeHTTP(w, r)
				return
			}
			WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		// Binary uploads declare their own limit (x-freya-max-body-bytes); the
		// handler validates the bytes by content, so the document validator
		// skips the body. Everything else is a small JSON document.
		limit, binary := int64(MaxBodyBytes), false
		if route.Operation != nil {
			if v, ok := route.Operation.Extensions[BodyLimitExtension]; ok {
				if n, ok := extensionInt(v); ok && n > 0 {
					limit, binary = n, true
				}
			}
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		body := r.Body
		if binary {
			// The validator buffers bodies it sees; keep the upload out of it.
			r.Body = http.NoBody
		}
		in := &openapi3filter.RequestValidationInput{Request: r, PathParams: params, Route: route,
			Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc, MultiError: false, ExcludeRequestBody: binary}}
		err = openapi3filter.ValidateRequest(r.Context(), in)
		if binary {
			r.Body = body // JSON bodies come back re-readable from the validator
		}
		if err != nil {
			var pe *openapi3filter.ParseError
			if errors.As(err, &pe) {
				WriteError(w, http.StatusBadRequest, ErrMalformed.Reason)
				return
			}
			WriteError(w, http.StatusBadRequest, ErrValidation.Reason)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// session attaches the actor resolved from the session cookie, if any.
func (s *Server) session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.sessions != nil {
			if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
				if actor, err := s.sessions.Resolve(r.Context(), c.Value); err == nil {
					r = r.WithContext(tenantctx.WithActor(r.Context(), actor))
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequireUser returns the signed-in user actor or ErrUnauthenticated.
func RequireUser(r *http.Request) (tenantctx.Actor, error) {
	a, ok := tenantctx.FromContext(r.Context())
	if !ok || a.Kind != tenantctx.KindUser && a.Kind != tenantctx.KindOperator {
		return tenantctx.Actor{}, ErrUnauthenticated
	}
	return a, nil
}

// ClearSessionCookie expires the session cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// SetSessionCookie installs the session cookie (host-only, HttpOnly, Strict).
func SetSessionCookie(w http.ResponseWriter, secret string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: secret, Path: "/", MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// BodyLimitExtension is the OpenAPI operation extension naming a per-route
// body limit in bytes for binary uploads.
const BodyLimitExtension = "x-freya-max-body-bytes"

func extensionInt(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int:
		return int64(x), true
	case int64:
		return x, true
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	}
	return 0, false
}
