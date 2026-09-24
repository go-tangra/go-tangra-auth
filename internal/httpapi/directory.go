package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/directory"
	"github.com/go-freya/freya/services/auth/internal/ldapdir"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// PermDirectoryManage gates the directory connection routes (feature 016).
const PermDirectoryManage = "directory:manage"

// DirectoryService is the directory connection service the handlers call
// (implemented by *directory.Service). Every method is scoped to tenantID,
// which the handlers always take from the actor.
type DirectoryService interface {
	List(ctx context.Context, a tenantctx.Actor, tenantID string) ([]directory.Connection, error)
	Get(ctx context.Context, a tenantctx.Actor, tenantID, id string) (directory.Connection, error)
	Create(ctx context.Context, a tenantctx.Actor, tenantID string, in directory.Input) (directory.Connection, error)
	Update(ctx context.Context, a tenantctx.Actor, tenantID, id string, in directory.Input) (directory.Connection, error)
	Remove(ctx context.Context, a tenantctx.Actor, tenantID, id string) error
	// Test checks settings without saving them. A zero in with a connID tests
	// the stored connection and persists last_test; otherwise connID only
	// supplies the stored password when in carries none.
	Test(ctx context.Context, a tenantctx.Actor, tenantID string, in directory.Input, connID string) (directory.TestResult, error)
}

// PermissionChecker answers FGA permission checks (*authz.Client).
type PermissionChecker interface {
	Allowed(ctx context.Context, tenantID, userID string, p authz.PermissionRef) (bool, error)
}

// DirectoryDeps wires the directory connection routes. With Enabled false
// the routes are still mounted but answer 404 before any other check.
type DirectoryDeps struct {
	Enabled     bool
	Directories DirectoryService
	Authz       PermissionChecker
}

// Directory refusals (closed vocabulary, research D9).
var (
	errDirInvalidFilter  = &Error{http.StatusBadRequest, "invalid_filter"}
	errDirInvalidBase    = &Error{http.StatusBadRequest, "invalid_base"}
	errDirInvalidURL     = &Error{http.StatusBadRequest, "invalid_url"}
	errDirInvalidCA      = &Error{http.StatusBadRequest, "invalid_ca"}
	errDirInsecure       = &Error{http.StatusBadRequest, "insecure_transport"}
	errDirTargetRefused  = &Error{http.StatusUnprocessableEntity, "target_refused"}
	errDirDuplicate      = &Error{http.StatusConflict, "duplicate"}
	errDirLimitReached   = &Error{http.StatusConflict, "limit_reached"}
	errDirRateLimited    = &Error{http.StatusTooManyRequests, "rate_limited"}
	errDirUnreachable    = &Error{http.StatusBadGateway, "unreachable"}
	errDirTLS            = &Error{http.StatusBadGateway, "tls_failed"}
	errDirInvalidCreds   = &Error{http.StatusBadGateway, "invalid_credentials"}
	errDirBaseNotFound   = &Error{http.StatusBadGateway, "base_not_found"}
	errDirDirectoryError = &Error{http.StatusBadGateway, "directory_error"}
	errDirTimeout        = &Error{http.StatusGatewayTimeout, "timeout"}
)

// directoryError maps service and ldapdir errors to closed reasons. Anything
// else stays as is and becomes 500 "internal" (the text goes to the log only).
func directoryError(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, directory.ErrNotFound), errors.Is(err, tenantctx.ErrCrossTenant):
		return ErrNotFound
	case errors.Is(err, directory.ErrValidation):
		return ErrValidation
	case errors.Is(err, directory.ErrInsecureTransport):
		return errDirInsecure
	case errors.Is(err, directory.ErrDuplicate):
		return errDirDuplicate
	case errors.Is(err, directory.ErrLimitReached):
		return errDirLimitReached
	case errors.Is(err, directory.ErrRateLimited):
		return errDirRateLimited
	case errors.Is(err, ldapdir.ErrInvalidURL):
		return errDirInvalidURL
	case errors.Is(err, ldapdir.ErrInvalidCA):
		return errDirInvalidCA
	case errors.Is(err, ldapdir.ErrInvalidFilter):
		return errDirInvalidFilter
	case errors.Is(err, ldapdir.ErrInvalidBase):
		return errDirInvalidBase
	case errors.Is(err, ldapdir.ErrTargetRefused):
		return errDirTargetRefused
	case errors.Is(err, ldapdir.ErrUnreachable):
		return errDirUnreachable
	case errors.Is(err, ldapdir.ErrTLS):
		return errDirTLS
	case errors.Is(err, ldapdir.ErrInvalidCredentials):
		return errDirInvalidCreds
	case errors.Is(err, ldapdir.ErrBaseNotFound):
		return errDirBaseNotFound
	case errors.Is(err, ldapdir.ErrTimeout):
		return errDirTimeout
	case errors.Is(err, ldapdir.ErrDirectory):
		return errDirDirectoryError
	}
	return err
}

// RequirePermission returns the actor when they hold perm in their tenant:
// the built-in owner/admin roles pass without an FGA round trip, any other
// role needs an FGA grant. An FGA failure refuses (fail closed).
func RequirePermission(r *http.Request, az PermissionChecker, perm string) (tenantctx.Actor, error) {
	a, err := RequireUser(r)
	if err != nil {
		return tenantctx.Actor{}, err
	}
	if hasAny(a.Roles, "owner", "admin") {
		return a, nil
	}
	ref, err := authz.ParsePermissionRef(perm)
	if err != nil || az == nil || a.TenantID == "" || a.UserID == "" {
		return tenantctx.Actor{}, ErrForbidden
	}
	ok, err := az.Allowed(r.Context(), a.TenantID, a.UserID, ref)
	if err != nil || !ok {
		return tenantctx.Actor{}, ErrForbidden
	}
	return a, nil
}

// RegisterDirectory mounts the directory connection routes.
func (s *Server) RegisterDirectory(d DirectoryDeps) {
	s.MustHandle("GET", "/api/v1/admin/directories", s.directoryRoute(d, s.listDirectories))
	s.MustHandle("POST", "/api/v1/admin/directories", s.directoryRoute(d, s.createDirectory))
	s.MustHandle("POST", "/api/v1/admin/directories/test", s.directoryRoute(d, s.testDirectory))
	s.MustHandle("GET", "/api/v1/admin/directories/{id}", s.directoryRoute(d, s.getDirectory))
	s.MustHandle("PUT", "/api/v1/admin/directories/{id}", s.directoryRoute(d, s.updateDirectory))
	s.MustHandle("POST", "/api/v1/admin/directories/{id}/remove", s.directoryRoute(d, s.removeDirectory))
	s.MustHandle("POST", "/api/v1/admin/directories/{id}/test", s.directoryRoute(d, s.testSavedDirectory))
}

type directoryHandler func(w http.ResponseWriter, r *http.Request, d DirectoryDeps, a *tenantctx.Actor)

// directoryRoute answers 404 when the feature is off, then applies gate D.
func (s *Server) directoryRoute(d DirectoryDeps, h directoryHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !d.Enabled || d.Directories == nil {
			Fail(w, r, nil, ErrNotFound)
			return
		}
		a, err := RequirePermission(r, d.Authz, PermDirectoryManage)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		h(w, r, d, &a)
	}
}

func (s *Server) listDirectories(w http.ResponseWriter, r *http.Request, d DirectoryDeps, a *tenantctx.Actor) {
	conns, err := d.Directories.List(r.Context(), *a, a.TenantID)
	if err != nil {
		Fail(w, r, s.rt.Logger(), directoryError(err))
		return
	}
	if conns == nil {
		conns = []directory.Connection{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": conns})
}

func (s *Server) createDirectory(w http.ResponseWriter, r *http.Request, d DirectoryDeps, a *tenantctx.Actor) {
	var in directory.Input
	if err := DecodeJSON(r, &in); err != nil {
		Fail(w, r, nil, err)
		return
	}
	c, err := d.Directories.Create(r.Context(), *a, a.TenantID, in)
	if err != nil {
		Fail(w, r, s.rt.Logger(), directoryError(err))
		return
	}
	WriteJSON(w, http.StatusCreated, c)
}

func (s *Server) getDirectory(w http.ResponseWriter, r *http.Request, d DirectoryDeps, a *tenantctx.Actor) {
	c, err := d.Directories.Get(r.Context(), *a, a.TenantID, r.PathValue("id"))
	if err != nil {
		Fail(w, r, s.rt.Logger(), directoryError(err))
		return
	}
	WriteJSON(w, http.StatusOK, c)
}

func (s *Server) updateDirectory(w http.ResponseWriter, r *http.Request, d DirectoryDeps, a *tenantctx.Actor) {
	var in directory.Input
	if err := DecodeJSON(r, &in); err != nil {
		Fail(w, r, nil, err)
		return
	}
	c, err := d.Directories.Update(r.Context(), *a, a.TenantID, r.PathValue("id"), in)
	if err != nil {
		Fail(w, r, s.rt.Logger(), directoryError(err))
		return
	}
	WriteJSON(w, http.StatusOK, c)
}

func (s *Server) removeDirectory(w http.ResponseWriter, r *http.Request, d DirectoryDeps, a *tenantctx.Actor) {
	if err := d.Directories.Remove(r.Context(), *a, a.TenantID, r.PathValue("id")); err != nil {
		Fail(w, r, s.rt.Logger(), directoryError(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// directoryTestInput is the unsaved-test body: the connection input plus an
// optional connection_id whose stored password is reused when bind_password
// is omitted.
type directoryTestInput struct {
	directory.Input
	ConnectionID string `json:"connection_id"`
}

func (s *Server) testDirectory(w http.ResponseWriter, r *http.Request, d DirectoryDeps, a *tenantctx.Actor) {
	var in directoryTestInput
	if err := DecodeJSON(r, &in); err != nil {
		Fail(w, r, nil, err)
		return
	}
	res, err := d.Directories.Test(r.Context(), *a, a.TenantID, in.Input, in.ConnectionID)
	if err != nil {
		Fail(w, r, s.rt.Logger(), directoryError(err))
		return
	}
	WriteJSON(w, http.StatusOK, res)
}

// testSavedDirectory tests the stored settings (zero input), so the service
// persists last_test.
func (s *Server) testSavedDirectory(w http.ResponseWriter, r *http.Request, d DirectoryDeps, a *tenantctx.Actor) {
	res, err := d.Directories.Test(r.Context(), *a, a.TenantID, directory.Input{}, r.PathValue("id"))
	if err != nil {
		Fail(w, r, s.rt.Logger(), directoryError(err))
		return
	}
	WriteJSON(w, http.StatusOK, res)
}
