package tenant

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/authz"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// Errors.
var (
	ErrNotOperator = errors.New("forbidden")
	ErrValidation  = errors.New("validation_failed")
)

// Revoker ends every session of a tenant (the session manager).
type Revoker interface {
	RevokeTenant(ctx context.Context, tenantID, reason string) error
}

// ReasonSuspended mirrors session.ReasonSuspended without importing it.
const ReasonSuspended = "tenant_suspended"

// Inviter creates the first owner invitation (the invite service).
type Inviter interface {
	Create(ctx context.Context, actor tenantctx.Actor, tenantID, email string, roleIDs []string) (string, error)
}

// Store is the tenant persistence.
type Store interface {
	InsertTenant(ctx context.Context, t store.Tenant) error
	Tenant(ctx context.Context, id string) (store.Tenant, error)
	ListTenants(ctx context.Context) ([]store.Tenant, error)
	UpdateTenantStatus(ctx context.Context, id, status string) error
	UpdateTenantPolicy(ctx context.Context, id string, policy []byte) error
	InsertRole(ctx context.Context, r store.Role) error
}

// BuiltinRoles every tenant starts with.
var BuiltinRoles = []string{"owner", "admin", "member"}

// Service manages tenant lifecycle and policy.
type Service struct {
	st       Store
	invites  Inviter
	sessions Revoker
	authz    *authz.Client
	cache    *cache.Cache
	audit    *audit.Writer
	now      func() time.Time
	// OnCreated runs after a tenant and its builtin roles exist (permission seeding).
	OnCreated func(ctx context.Context, tenantID string)
}

// New wires the service.
func New(st Store, inv Inviter, sm Revoker, az *authz.Client, c *cache.Cache, a *audit.Writer) *Service {
	return &Service{st: st, invites: inv, sessions: sm, authz: az, cache: c, audit: a, now: time.Now}
}

// View is the operator listing projection.
type View struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	Kind        string `json:"kind"`
	CreatedAt   string `json:"created_at"`
}

func requireOperator(ctx context.Context) (tenantctx.Actor, error) {
	a, ok := tenantctx.FromContext(ctx)
	if !ok || a.Kind != tenantctx.KindOperator {
		return tenantctx.Actor{}, ErrNotOperator
	}
	return a, nil
}

// List returns every tenant (operators only).
func (s *Service) List(ctx context.Context) ([]View, error) {
	if _, err := requireOperator(ctx); err != nil {
		return nil, err
	}
	tenants, err := s.st.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, View{ID: t.ID, Slug: t.Slug, DisplayName: t.DisplayName, Status: t.Status, Kind: t.Kind, CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339)})
	}
	return out, nil
}

// Created reports a new tenant and its owner invitation.
type Created struct {
	Tenant       View   `json:"tenant"`
	InvitationID string `json:"invitation_id"`
}

// Create makes a customer tenant with the default policy, built-in roles and
// an owner invitation.
func (s *Service) Create(ctx context.Context, slug, displayName, ownerEmail string) (Created, error) {
	op, err := requireOperator(ctx)
	if err != nil {
		return Created{}, err
	}
	if _, err := ParseSlug(slug); err != nil {
		return Created{}, ErrValidation
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || len(displayName) > 120 || !strings.Contains(ownerEmail, "@") {
		return Created{}, ErrValidation
	}
	now := s.now()
	t := store.Tenant{ID: store.NewID(), Slug: slug, DisplayName: displayName, Status: "active", Kind: "customer", Policy: DefaultPolicy().JSON(), CreatedAt: now, UpdatedAt: now}
	if err := s.st.InsertTenant(ctx, t); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return Created{}, ErrValidation
		}
		return Created{}, err
	}
	ownerRole := ""
	var tuples []authz.Tuple
	for _, r := range BuiltinRoles {
		role := store.Role{ID: store.NewID(), TenantID: t.ID, Slug: r, DisplayName: strings.ToUpper(r[:1]) + r[1:], Builtin: true}
		if err := s.st.InsertRole(ctx, role); err != nil {
			return Created{}, err
		}
		if r == "owner" {
			ownerRole = role.ID
		}
		tuples = append(tuples, authz.RoleTenantTuple(t.ID, r))
	}
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	if err := s.authz.Write(sys, t.ID, tuples, nil); err != nil {
		return Created{}, err
	}
	if s.OnCreated != nil {
		s.OnCreated(ctx, t.ID)
	}
	inv, err := s.invites.Create(tenantctx.WithOperatorGrant(ctx, "tenant-creation", t.ID), op, t.ID, ownerEmail, []string{ownerRole})
	if err != nil {
		return Created{}, err
	}
	s.emit(audit.Event{Type: audit.TenantCreated, TenantID: t.ID, ActorKind: "operator", ActorUserID: op.UserID, Outcome: "ok", SubjectKind: "tenant", SubjectID: t.ID, Details: map[string]any{"slug": slug}})
	return Created{Tenant: View{ID: t.ID, Slug: slug, DisplayName: displayName, Status: "active", Kind: "customer", CreatedAt: now.UTC().Format(time.RFC3339)}, InvitationID: inv}, nil
}

// Suspend blocks the tenant and ends every session in it.
func (s *Service) Suspend(ctx context.Context, id string) error {
	op, err := requireOperator(ctx)
	if err != nil {
		return err
	}
	t, err := s.st.Tenant(ctx, id)
	if err != nil {
		return err
	}
	if t.Kind == "platform" {
		return ErrValidation
	}
	if t.Status != "suspended" {
		if err := s.st.UpdateTenantStatus(ctx, id, "suspended"); err != nil {
			return err
		}
	}
	if err := s.sessions.RevokeTenant(ctx, id, ReasonSuspended); err != nil {
		return err
	}
	if s.cache != nil {
		_, _ = s.cache.BumpTenantVersion(ctx, id)
	}
	s.emit(audit.Event{Type: audit.TenantSuspended, TenantID: id, ActorKind: "operator", ActorUserID: op.UserID, Outcome: "ok", SubjectKind: "tenant", SubjectID: id})
	return nil
}

// Reactivate restores a suspended tenant; sessions are not restored.
func (s *Service) Reactivate(ctx context.Context, id string) error {
	op, err := requireOperator(ctx)
	if err != nil {
		return err
	}
	t, err := s.st.Tenant(ctx, id)
	if err != nil {
		return err
	}
	if t.Status == "active" {
		return nil
	}
	if err := s.st.UpdateTenantStatus(ctx, id, "active"); err != nil {
		return err
	}
	if s.cache != nil {
		_, _ = s.cache.BumpTenantVersion(ctx, id)
	}
	s.emit(audit.Event{Type: audit.TenantReactivated, TenantID: id, ActorKind: "operator", ActorUserID: op.UserID, Outcome: "ok", SubjectKind: "tenant", SubjectID: id})
	return nil
}

// GetPolicy returns the effective policy of a tenant.
func (s *Service) GetPolicy(ctx context.Context, tenantID string) (Policy, error) {
	if err := s.authz.Guard().Require(ctx, tenantID); err != nil {
		return Policy{}, err
	}
	t, err := s.st.Tenant(ctx, tenantID)
	if err != nil {
		return Policy{}, err
	}
	return ParsePolicy(t.Policy, t.Kind == "platform")
}

// UpdatePolicy validates and stores a policy; platform tenants keep MFA.
func (s *Service) UpdatePolicy(ctx context.Context, tenantID string, p Policy) (Policy, error) {
	a, ok := tenantctx.FromContext(ctx)
	if !ok {
		return Policy{}, tenantctx.ErrNoActor
	}
	if err := s.authz.Guard().Require(ctx, tenantID); err != nil {
		return Policy{}, err
	}
	t, err := s.st.Tenant(ctx, tenantID)
	if err != nil {
		return Policy{}, err
	}
	if t.Kind == "platform" {
		p.MFARequired = true
	}
	if err := p.Validate(); err != nil {
		return Policy{}, errors.Join(ErrValidation, err)
	}
	if err := s.st.UpdateTenantPolicy(ctx, tenantID, p.JSON()); err != nil {
		return Policy{}, err
	}
	if s.cache != nil {
		_, _ = s.cache.BumpTenantVersion(ctx, tenantID)
	}
	s.emit(audit.Event{Type: audit.PolicyUpdated, TenantID: tenantID, ActorKind: string(a.Kind), ActorUserID: a.UserID, Outcome: "ok", SubjectKind: "tenant", SubjectID: tenantID, Details: map[string]any{"policy": string(p.JSON())}})
	return p, nil
}

func (s *Service) emit(e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Emit(e)
	}
}
