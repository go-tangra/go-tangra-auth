package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
)

// US3Deps are the role and permission services.
type US3Deps struct {
	Roles    *authz.Roles
	Registry *authz.Registry
}

var errBuiltin = &Error{http.StatusForbidden, "builtin"}

func roleError(err error) error {
	switch {
	case errors.Is(err, authz.ErrBuiltin):
		return errBuiltin
	case errors.Is(err, authz.ErrRoleRef):
		return ErrValidation
	}
	return adminError(err)
}

// RegisterUS3 mounts role and permission routes.
func (s *Server) RegisterUS3(d US3Deps) {
	s.MustHandle("GET", "/api/v1/admin/roles", s.listRoles(d))
	s.MustHandle("GET", "/api/v1/roles", s.listRoleNames(d))
	s.MustHandle("POST", "/api/v1/admin/roles", s.createRole(d))
	s.MustHandle("PUT", "/api/v1/admin/roles/{id}", s.updateRole(d))
	s.MustHandle("POST", "/api/v1/admin/roles/{id}/remove", s.removeRole(d))
	s.MustHandle("GET", "/api/v1/admin/permissions", s.listPermissions(d))
}

type roleBody struct {
	Slug        string   `json:"slug"`
	DisplayName string   `json:"display_name"`
	Permissions []string `json:"permissions"`
	// Fields of the Role schema a client may echo back; ignored on write.
	ID      string `json:"id,omitempty"`
	Builtin bool   `json:"builtin,omitempty"`
}

func (s *Server) listRoles(d US3Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		roles, err := d.Roles.List(r.Context(), a.TenantID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), roleError(err))
			return
		}
		WriteJSON(w, http.StatusOK, roles)
	}
}

func (s *Server) createRole(d US3Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in roleBody
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		role, err := d.Roles.Create(r.Context(), a.TenantID, in.Slug, in.DisplayName, in.Permissions)
		if err != nil {
			Fail(w, r, s.rt.Logger(), roleError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, role)
	}
}

func (s *Server) updateRole(d US3Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in roleBody
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		role, err := d.Roles.Update(r.Context(), a.TenantID, r.PathValue("id"), in.DisplayName, in.Permissions)
		if err != nil {
			Fail(w, r, s.rt.Logger(), roleError(err))
			return
		}
		WriteJSON(w, http.StatusOK, role)
	}
}

func (s *Server) removeRole(d US3Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Roles.Remove(r.Context(), a.TenantID, r.PathValue("id")); err != nil {
			Fail(w, r, s.rt.Logger(), roleError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) listPermissions(d US3Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		perms, err := d.Registry.List(r.Context(), a.TenantID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), roleError(err))
			return
		}
		WriteJSON(w, http.StatusOK, perms)
	}
}

// listRoleNames is the member-level subject picker: slug and display name only.
func (s *Server) listRoleNames(d US3Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireUser(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		names, err := d.Roles.Names(r.Context(), a.TenantID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), roleError(err))
			return
		}
		WriteJSON(w, http.StatusOK, names)
	}
}
