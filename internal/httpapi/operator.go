package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// OperatorTenantHeader lets an operator with an active grant act inside a
// customer tenant on the admin routes.
const OperatorTenantHeader = "X-Operator-Tenant"

// US5Deps are the operator, policy and client services.
type US5Deps struct {
	Tenants *tenant.Service
	Grants  *tenant.Grants
	Clients ClientStore
	Audit   *audit.Writer
}

// ClientStore persists client applications.
type ClientStore interface {
	InsertClient(ctx context.Context, c store.ClientApplication) error
	ListClients(ctx context.Context, tenantID string) ([]store.ClientApplication, error)
}

func operatorError(err error) error {
	switch {
	case errors.Is(err, tenant.ErrNotOperator):
		return ErrForbidden
	case errors.Is(err, tenant.ErrValidation), errors.Is(err, tenant.ErrPolicy):
		return ErrValidation
	case errors.Is(err, tenant.ErrNoGrant):
		return ErrForbidden
	}
	return adminError(err)
}

// RegisterUS5 mounts operator, policy and client routes.
func (s *Server) RegisterUS5(d US5Deps) {
	s.grants = d.Grants
	s.MustHandle("GET", "/api/v1/operator/tenants", s.listTenants(d))
	s.MustHandle("POST", "/api/v1/operator/tenants", s.createTenant(d))
	s.MustHandle("POST", "/api/v1/operator/tenants/{id}/suspend", s.tenantStatus(d, "suspend"))
	s.MustHandle("POST", "/api/v1/operator/tenants/{id}/reactivate", s.tenantStatus(d, "reactivate"))
	s.MustHandle("POST", "/api/v1/operator/grants", s.createGrant(d))
	s.MustHandle("GET", "/api/v1/admin/policy", s.getPolicy(d))
	s.MustHandle("PUT", "/api/v1/admin/policy", s.updatePolicy(d))
	s.MustHandle("GET", "/api/v1/admin/clients", s.listClients(d))
	s.MustHandle("POST", "/api/v1/admin/clients", s.createClient(d))
}

func requireOperator(r *http.Request) (tenantctx.Actor, error) {
	a, err := RequireUser(r)
	if err != nil {
		return tenantctx.Actor{}, err
	}
	if a.Kind != tenantctx.KindOperator {
		return tenantctx.Actor{}, ErrForbidden
	}
	return a, nil
}

func (s *Server) listTenants(d US5Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := requireOperator(r); err != nil {
			Fail(w, r, nil, err)
			return
		}
		list, err := d.Tenants.List(r.Context())
		if err != nil {
			Fail(w, r, s.rt.Logger(), operatorError(err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": list})
	}
}

func (s *Server) createTenant(d US5Deps) http.HandlerFunc {
	type body struct {
		Slug        string `json:"slug"`
		DisplayName string `json:"display_name"`
		OwnerEmail  string `json:"owner_email"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := requireOperator(r); err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		created, err := d.Tenants.Create(r.Context(), in.Slug, in.DisplayName, in.OwnerEmail)
		if err != nil {
			Fail(w, r, s.rt.Logger(), operatorError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, created)
	}
}

func (s *Server) tenantStatus(d US5Deps, op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := requireOperator(r); err != nil {
			Fail(w, r, nil, err)
			return
		}
		var err error
		if op == "suspend" {
			err = d.Tenants.Suspend(r.Context(), r.PathValue("id"))
		} else {
			err = d.Tenants.Reactivate(r.Context(), r.PathValue("id"))
		}
		if err != nil {
			Fail(w, r, s.rt.Logger(), operatorError(err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) createGrant(d US5Deps) http.HandlerFunc {
	type body struct {
		TenantID string `json:"tenant_id"`
		Reason   string `json:"reason"`
		Duration string `json:"duration"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := requireOperator(r); err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		dur, err := time.ParseDuration(in.Duration)
		if err != nil {
			Fail(w, r, nil, ErrValidation)
			return
		}
		g, err := d.Grants.Create(r.Context(), in.TenantID, in.Reason, dur)
		if err != nil {
			Fail(w, r, s.rt.Logger(), operatorError(err))
			return
		}
		WriteJSON(w, http.StatusCreated, g)
	}
}

func (s *Server) getPolicy(d US5Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ctx, err := s.adminScope(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		p, err := d.Tenants.GetPolicy(ctx, a.TenantID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), operatorError(err))
			return
		}
		WriteJSON(w, http.StatusOK, p)
	}
}

func (s *Server) updatePolicy(d US5Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ctx, err := s.adminScope(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		p := tenant.DefaultPolicy()
		if err := DecodeJSON(r, &p); err != nil {
			Fail(w, r, nil, err)
			return
		}
		got, err := d.Tenants.UpdatePolicy(ctx, a.TenantID, p)
		if err != nil {
			Fail(w, r, s.rt.Logger(), operatorError(err))
			return
		}
		WriteJSON(w, http.StatusOK, got)
	}
}

func (s *Server) listClients(d US5Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ctx, err := s.adminScope(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		clients, err := d.Clients.ListClients(ctx, a.TenantID)
		if err != nil {
			Fail(w, r, s.rt.Logger(), operatorError(err))
			return
		}
		out := make([]map[string]any, 0, len(clients))
		for _, c := range clients {
			out = append(out, map[string]any{"client_id": c.ClientID, "display_name": c.DisplayName, "redirect_uris": c.RedirectURIs, "public": c.Public})
		}
		WriteJSON(w, http.StatusOK, out)
	}
}

func (s *Server) createClient(d US5Deps) http.HandlerFunc {
	type body struct {
		DisplayName  string   `json:"display_name"`
		RedirectURIs []string `json:"redirect_uris"`
		Public       bool     `json:"public"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		a, ctx, err := s.adminScope(r)
		if err != nil {
			Fail(w, r, nil, err)
			return
		}
		var in body
		if err := DecodeJSON(r, &in); err != nil {
			Fail(w, r, nil, err)
			return
		}
		for _, u := range in.RedirectURIs {
			if !validRedirect(u) {
				Fail(w, r, nil, ErrValidation)
				return
			}
		}
		id, err := crypto.RandomToken(12)
		if err != nil {
			Fail(w, r, s.rt.Logger(), err)
			return
		}
		c := store.ClientApplication{ClientID: id, TenantID: a.TenantID, DisplayName: in.DisplayName, RedirectURIs: in.RedirectURIs, Public: in.Public}
		resp := map[string]any{"client_id": id, "display_name": in.DisplayName, "redirect_uris": in.RedirectURIs, "public": in.Public}
		if !in.Public {
			secret, err := crypto.RandomToken(32)
			if err != nil {
				Fail(w, r, s.rt.Logger(), err)
				return
			}
			h, err := crypto.HashPassword(secret, crypto.DefaultParams)
			if err != nil {
				Fail(w, r, s.rt.Logger(), err)
				return
			}
			c.SecretHash = &h
			resp["client_secret"] = secret // shown exactly once
		}
		if err := d.Clients.InsertClient(ctx, c); err != nil {
			Fail(w, r, s.rt.Logger(), operatorError(err))
			return
		}
		if d.Audit != nil {
			_ = d.Audit.Emit(audit.Event{Type: audit.ClientRegistered, TenantID: a.TenantID, ActorKind: string(a.Kind), ActorUserID: a.UserID, Outcome: "ok", SubjectKind: "client", SubjectID: id, Details: map[string]any{"public": in.Public}})
		}
		WriteJSON(w, http.StatusCreated, resp)
	}
}

func validRedirect(u string) bool {
	return len(u) <= 512 && (hasPrefix(u, "https://") || hasPrefix(u, "http://127.0.0.1") || hasPrefix(u, "http://localhost"))
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// adminScope resolves who is administering which tenant: a tenant owner or
// admin in their own tenant, or an operator inside a customer tenant named
// by the X-Operator-Tenant header, which requires an active grant.
func (s *Server) adminScope(r *http.Request) (tenantctx.Actor, context.Context, error) {
	a, err := RequireUser(r)
	if err != nil {
		return tenantctx.Actor{}, nil, err
	}
	ctx := r.Context()
	if target := r.Header.Get(OperatorTenantHeader); target != "" {
		if a.Kind != tenantctx.KindOperator || s.grants == nil {
			return tenantctx.Actor{}, nil, ErrForbidden
		}
		ctx, err = s.grants.Apply(ctx, target)
		if err != nil {
			return tenantctx.Actor{}, nil, operatorError(err)
		}
		a.TenantID = target
		a.Roles = []string{"owner"}
		return a, tenantctx.WithActor(ctx, a), nil
	}
	if !hasAny(a.Roles, "owner", "admin") && a.Kind != tenantctx.KindOperator {
		return tenantctx.Actor{}, nil, ErrForbidden
	}
	return a, ctx, nil
}
