package tenant

import (
	"context"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Grant limits (SR-006).
const (
	MaxGrant       = 4 * time.Hour
	MinGrantReason = 10
)

// ErrNoGrant means the operator has no active grant for the tenant.
var ErrNoGrant = tenantctx.ErrNoOperatorGrant

// GrantStore persists operator grants.
type GrantStore interface {
	InsertOperatorGrant(ctx context.Context, g store.OperatorGrant) error
	ActiveOperatorGrant(ctx context.Context, operatorID, tenantID string) (store.OperatorGrant, error)
	Tenant(ctx context.Context, id string) (store.Tenant, error)
}

// Grants issues and applies operator access grants.
type Grants struct {
	st    GrantStore
	audit *audit.Writer
	now   func() time.Time
}

// NewGrants wires the service.
func NewGrants(st GrantStore, a *audit.Writer) *Grants {
	return &Grants{st: st, audit: a, now: time.Now}
}

// GrantView is the API projection.
type GrantView struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
}

// Create issues a grant for the calling operator into a customer tenant.
func (g *Grants) Create(ctx context.Context, tenantID, reason string, duration time.Duration) (GrantView, error) {
	op, err := requireOperator(ctx)
	if err != nil {
		return GrantView{}, err
	}
	reason = strings.TrimSpace(reason)
	if len(reason) < MinGrantReason || len(reason) > 500 || duration <= 0 || duration > MaxGrant || !tenantctx.ValidTenantID(tenantID) {
		return GrantView{}, ErrValidation
	}
	t, err := g.st.Tenant(ctx, tenantID)
	if err != nil {
		return GrantView{}, err
	}
	if t.Kind == "platform" {
		return GrantView{}, ErrValidation
	}
	now := g.now()
	gr := store.OperatorGrant{ID: store.NewID(), OperatorUserID: op.UserID, TenantID: tenantID, Reason: reason, GrantedAt: now, ExpiresAt: now.Add(duration)}
	if err := g.st.InsertOperatorGrant(ctx, gr); err != nil {
		return GrantView{}, err
	}
	g.emit(audit.Event{Type: audit.OperatorGrantCreated, TenantID: tenantID, ActorKind: "operator", ActorUserID: op.UserID, Outcome: "ok", SubjectKind: "operator_grant", SubjectID: gr.ID,
		Details: map[string]any{"reason": reason, "expires_at": gr.ExpiresAt.UTC().Format(time.RFC3339)}})
	return GrantView{ID: gr.ID, TenantID: tenantID, Reason: reason, ExpiresAt: gr.ExpiresAt.UTC().Format(time.RFC3339)}, nil
}

// Apply lets an operator act inside tenantID: the active grant is attached
// to the context and its use audited; without one the call is refused.
func (g *Grants) Apply(ctx context.Context, tenantID string) (context.Context, error) {
	op, err := requireOperator(ctx)
	if err != nil {
		return ctx, err
	}
	if op.TenantID == tenantID {
		return ctx, nil
	}
	gr, err := g.st.ActiveOperatorGrant(ctx, op.UserID, tenantID)
	if err != nil {
		g.emit(audit.Event{Type: audit.CrossTenantRefused, TenantID: tenantID, ActorKind: "operator", ActorUserID: op.UserID, Outcome: "refused", Reason: "no_operator_grant"})
		return ctx, ErrNoGrant
	}
	if !g.now().Before(gr.ExpiresAt) {
		return ctx, ErrNoGrant
	}
	g.emit(audit.Event{Type: audit.OperatorGrantUsed, TenantID: tenantID, ActorKind: "operator", ActorUserID: op.UserID, Outcome: "ok", SubjectKind: "operator_grant", SubjectID: gr.ID})
	return tenantctx.WithOperatorGrant(ctx, gr.ID, tenantID), nil
}

func (g *Grants) emit(e audit.Event) {
	if g.audit != nil {
		_ = g.audit.Emit(e)
	}
}
