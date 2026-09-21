package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// GroupDeps wires the group administration routes (feature 004).
type GroupDeps struct {
	Groups *authz.Groups
}

// Group refusals (closed vocabulary from the OpenAPI document).
var (
	errNameTaken           = &Error{http.StatusConflict, "name_taken"}
	errMemberCountMismatch = &Error{http.StatusConflict, "member_count_mismatch"}
	errOwnerViaGroup       = &Error{http.StatusForbidden, "owner_via_group"}
)

func groupError(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, authz.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, authz.ErrNameTaken):
		return errNameTaken
	case errors.Is(err, authz.ErrInvalidName):
		return ErrValidation
	case errors.Is(err, authz.ErrMemberCountMismatch):
		return errMemberCountMismatch
	case errors.Is(err, authz.ErrOwnerViaGroup):
		return errOwnerViaGroup
	case errors.Is(err, authz.ErrSelfEscalation):
		return errSelfEscalation
	case errors.Is(err, tenantctx.ErrCrossTenant):
		return ErrNotFound
	}
	return err
}

// RegisterGroups mounts the group routes.
func (s *Server) RegisterGroups(d GroupDeps) {
	s.MustHandle("GET", "/api/v1/admin/groups", s.listGroups(d))
	s.MustHandle("POST", "/api/v1/admin/groups", s.createGroup(d))
	s.MustHandle("GET", "/api/v1/admin/groups/{id}", s.getGroup(d))
	s.MustHandle("PUT", "/api/v1/admin/groups/{id}", s.updateGroup(d))
	s.MustHandle("POST", "/api/v1/admin/groups/{id}/remove", s.deleteGroup(d))
	s.MustHandle("GET", "/api/v1/admin/groups/{id}/members", s.listGroupMembers(d))
	s.MustHandle("POST", "/api/v1/admin/groups/{id}/members", s.addGroupMembers(d))
	s.MustHandle("POST", "/api/v1/admin/groups/{id}/members/{user_id}/remove", s.removeGroupMember(d))
	s.MustHandle("PUT", "/api/v1/admin/groups/{id}/roles", s.setGroupRoles(d))
	s.MustHandle("GET", "/api/v1/admin/users/{id}/effective-roles", s.effectiveRoles(d))
	s.MustHandle("GET", "/api/v1/admin/users/{id}/groups", s.userGroups(d))
}

func groupJSON(v authz.GroupView) map[string]any {
	return map[string]any{"id": v.ID, "name": v.Name, "description": v.Description, "member_count": v.MemberCount, "roles": v.Roles,
		"created_at": v.CreatedAt.UTC().Format(time.RFC3339), "updated_at": v.UpdatedAt.UTC().Format(time.RFC3339)}
}

func (s *Server) listGroups(d GroupDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		groups, err := d.Groups.List(r.Context(), a.TenantID, r.URL.Query().Get("q"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		items := make([]map[string]any, 0, len(groups))
		for _, g := range groups {
			items = append(items, groupJSON(g))
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	}
}

type groupInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) createGroup(d GroupDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in groupInput
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		g, err := d.Groups.Create(r.Context(), a.TenantID, in.Name, in.Description)
		if err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, groupJSON(authz.GroupView{Group: g, Roles: []string{}}))
	}
}

func (s *Server) getGroup(d GroupDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		g, err := d.Groups.Get(r.Context(), a.TenantID, r.PathValue("id"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		WriteJSON(w, http.StatusOK, groupJSON(g))
	}
}

func (s *Server) updateGroup(d GroupDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in groupInput
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		if _, err := d.Groups.Update(r.Context(), a.TenantID, r.PathValue("id"), in.Name, in.Description); err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		g, err := d.Groups.Get(r.Context(), a.TenantID, r.PathValue("id"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		WriteJSON(w, http.StatusOK, groupJSON(g))
	}
}

func (s *Server) deleteGroup(d GroupDeps) http.HandlerFunc {
	type body struct {
		MemberCount int `json:"member_count"`
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
		if err := d.Groups.Delete(r.Context(), a.TenantID, r.PathValue("id"), in.MemberCount); err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) listGroupMembers(d GroupDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var after time.Time
		if c := r.URL.Query().Get("cursor"); c != "" {
			t, err := time.Parse(time.RFC3339Nano, c)
			if err != nil {
				Fail(w, r, nil, ErrValidation)
				return
			}
			after = t
		}
		members, err := d.Groups.Members(r.Context(), a.TenantID, r.PathValue("id"), after, authz.GroupBatchMax)
		if err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		items := make([]map[string]any, 0, len(members))
		var next string
		for _, m := range members {
			items = append(items, map[string]any{"user_id": m.UserID, "email": m.Email, "display_name": m.DisplayName, "status": m.Status,
				"avatar_url": tenantctx.AvatarURL(m.UserID, m.AvatarID), "added_at": m.AddedAt.UTC().Format(time.RFC3339Nano)})
			next = m.AddedAt.UTC().Format(time.RFC3339Nano)
		}
		if len(members) < authz.GroupBatchMax {
			next = ""
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next": next})
	}
}

func (s *Server) addGroupMembers(d GroupDeps) http.HandlerFunc {
	type body struct {
		UserIDs []string `json:"user_ids"`
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
		n, err := d.Groups.AddMembers(r.Context(), a.TenantID, r.PathValue("id"), in.UserIDs)
		if err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"added": n})
	}
}

func (s *Server) removeGroupMember(d GroupDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		if err := d.Groups.RemoveMember(r.Context(), a.TenantID, r.PathValue("id"), r.PathValue("user_id")); err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) setGroupRoles(d GroupDeps) http.HandlerFunc {
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
		slugs, err := d.Groups.SetRoles(r.Context(), a.TenantID, r.PathValue("id"), in.RoleIDs)
		if err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"roles": slugs})
	}
}

func (s *Server) effectiveRoles(d GroupDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		roles, err := d.Groups.EffectiveRoles(r.Context(), a.TenantID, r.PathValue("id"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": roles})
	}
}

func (s *Server) userGroups(d GroupDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := RequireAdmin(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		groups, err := d.Groups.UserGroups(r.Context(), a.TenantID, r.PathValue("id"))
		if err != nil {
			Fail(w, r, s.rt.Logger(), groupError(err))
			return
		}
		items := make([]map[string]any, 0, len(groups))
		for _, g := range groups {
			items = append(items, map[string]any{"id": g.ID, "name": g.Name})
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	}
}
