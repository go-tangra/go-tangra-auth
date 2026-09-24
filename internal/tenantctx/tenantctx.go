package tenantctx

import (
	"context"
	"errors"
	"regexp"

	"github.com/go-tangra/go-tangra/v4/authn"
)

// Kind of actor.
type Kind string

// Actor kinds.
const (
	KindUser     Kind = "user"
	KindOperator Kind = "operator"
	KindService  Kind = "service"
	KindSystem   Kind = "system"
)

// Actor is the verified caller of a request.
type Actor struct {
	Kind      Kind
	UserID    string
	TenantID  string // for users/operators: their own tenant
	SessionID string
	Roles     []string
	AMR       []string // authentication methods of the session
	ServiceID string   // SPIFFE ID for services
	// Profile (feature 004): shown by the platform; never the phone number.
	DisplayName string
	AvatarURL   string
}

// AvatarURL is the gateway-relative, content-addressed address of a user's
// avatar; empty when the user has none.
func AvatarURL(userID string, avatarID *string) string {
	if avatarID == nil || *avatarID == "" {
		return ""
	}
	return "/api/v1/users/" + userID + "/avatar/" + *avatarID
}

// HasRole reports whether the actor holds the role slug.
func (a Actor) HasRole(slug string) bool {
	for _, r := range a.Roles {
		if r == slug {
			return true
		}
	}
	return false
}

// IsOwner / IsAdmin follow the built-in role hierarchy (owner ⊃ admin ⊃ member).
func (a Actor) IsOwner() bool { return a.HasRole("owner") }
func (a Actor) IsAdmin() bool { return a.IsOwner() || a.HasRole("admin") }

type actorKey struct{}
type grantKey struct{}

// Grant is an active operator access grant into a tenant (SR-006).
type Grant struct {
	ID       string
	TenantID string
}

// WithActor stores the actor.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// FromContext returns the actor.
func FromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(Actor)
	return a, ok
}

// WithOperatorGrant attaches an active grant.
func WithOperatorGrant(ctx context.Context, id, tenantID string) context.Context {
	return context.WithValue(ctx, grantKey{}, Grant{ID: id, TenantID: tenantID})
}

// OperatorGrant returns the attached grant.
func OperatorGrant(ctx context.Context) (Grant, bool) {
	g, ok := ctx.Value(grantKey{}).(Grant)
	return g, ok
}

// ActorFromService builds a service actor from the verified peer.
func ActorFromService(p authn.PeerIdentity) Actor {
	return Actor{Kind: KindService, ServiceID: p.ID.String()}
}

var tenantIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidTenantID reports whether s is a UUID.
func ValidTenantID(s string) bool { return tenantIDRE.MatchString(s) }

// Errors.
var (
	ErrNoActor         = errors.New("tenantctx: no actor")
	ErrCrossTenant     = errors.New("tenantctx: cross-tenant access refused")
	ErrNoOperatorGrant = errors.New("tenantctx: operator access requires an active grant")
)

// Refusal describes a cross-tenant refusal for auditing.
type Refusal struct {
	Actor        Actor
	ActorTenant  string
	TargetTenant string
	Reason       string
}

// Guard enforces tenant scoping on every access path (SR-001).
type Guard struct {
	OnRefusal func(Refusal)
}

// Require verifies that the actor in ctx may act inside tenantID.
func (g Guard) Require(ctx context.Context, tenantID string) error {
	a, ok := FromContext(ctx)
	if !ok {
		return ErrNoActor
	}
	if tenantID == "" {
		g.refuse(a, tenantID, "empty_tenant")
		return ErrCrossTenant
	}
	switch a.Kind {
	case KindService, KindSystem:
		return nil
	case KindOperator:
		if a.TenantID == tenantID {
			return nil
		}
		if gr, ok := OperatorGrant(ctx); ok && gr.TenantID == tenantID {
			return nil
		}
		g.refuse(a, tenantID, "no_operator_grant")
		return ErrNoOperatorGrant
	default:
		if a.TenantID == tenantID {
			return nil
		}
		g.refuse(a, tenantID, "cross_tenant")
		return ErrCrossTenant
	}
}

func (g Guard) refuse(a Actor, target, reason string) {
	if g.OnRefusal != nil {
		g.OnRefusal(Refusal{Actor: a, ActorTenant: a.TenantID, TargetTenant: target, Reason: reason})
	}
}
