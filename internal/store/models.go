package store

import (
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/permref"
)

// Tenant row.
type Tenant struct {
	ID, Slug, DisplayName, Status, Kind string
	Policy                              []byte
	CreatedAt, UpdatedAt                time.Time
}

// User row.
type User struct {
	ID, TenantID, Email, DisplayName, Status string
	PasswordHash                             *string
	PasswordChangedAt                        *time.Time
	MFAEnabled                               bool
	MFASecretEnc                             []byte
	MFALastCounter                           int64
	CreatedAt, UpdatedAt                     time.Time
	LastSigninAt                             *time.Time
	// Profile (feature 004). Phone is PII: never logged or exposed beyond self/admin.
	FirstName, LastName, Phone string
	AvatarID                   *string
	DisplayNameExplicit        bool
	ProfileUpdatedAt           *time.Time
	// Filled by ListUsers only (feature 016): the directory origin, and the
	// pending (not accepted, not revoked) invitation of an invited user.
	Directory    *DirectoryLink
	InvitationID *string
}

// ProfilePatch is the writable part of a profile.
type ProfilePatch struct {
	FirstName, LastName, Phone, DisplayName string
	DisplayNameExplicit                     bool
}

// Group row.
type Group struct {
	ID, TenantID, Name, Description string
	CreatedBy                       *string
	CreatedAt, UpdatedAt            time.Time
}

// GroupMember row joined with the user's public profile.
type GroupMember struct {
	UserID, Email, DisplayName, Status string
	AvatarID                           *string
	AddedAt                            time.Time
}

// EffectiveRoleRow is one (role, source) pair of a user.
type EffectiveRoleRow struct {
	RoleID, Slug, Source string // source: direct | group
	GroupID, GroupName   string
}

// Avatar row: one normalised picture per user, content-addressed.
type Avatar struct {
	ID, TenantID, UserID, ContentType string
	Bytes                             []byte
	CreatedAt                         time.Time
}

// PublicProfile is what any member of the tenant may see about another.
type PublicProfile struct {
	ID, DisplayName string
	AvatarID        *string
	Email           string // filled by SearchProfiles only
}

// Role origins (feature 019).
const (
	OriginBuiltin = "builtin"
	OriginModule  = "module"
	OriginCustom  = "custom"
)

// Role row. Origin is builtin, module or custom (empty: derived from
// Builtin on insert); Module and ModuleSlug are set iff Origin is module.
type Role struct {
	ID, TenantID, Slug, DisplayName string
	Builtin                         bool
	CreatedAt, UpdatedAt            time.Time
	Origin, Module, ModuleSlug      string
	Description                     string
	RetiredAt                       *time.Time
}

// OriginOf returns the role origin, deriving it from Builtin when unset.
func (r Role) OriginOf() string {
	switch {
	case r.Origin != "":
		return r.Origin
	case r.Builtin:
		return OriginBuiltin
	}
	return OriginCustom
}

// Permission is one row of a tenant's permission catalogue; Module is empty
// for legacy (pre-019) rows.
type Permission struct {
	Module, Resource, Action, Description string
}

// Ref returns the permission reference.
func (p Permission) Ref() permref.Ref {
	return permref.Ref{Module: p.Module, Resource: p.Resource, Action: p.Action}
}

// Module is a platform module of the catalogue (feature 019).
type Module struct {
	Name, DisplayName       string
	RegisteredAt, UpdatedAt time.Time
	RetiredAt               *time.Time
}

// ModulePermission is a permission of the platform catalogue.
type ModulePermission struct {
	Module, Resource, Action, Description string
	RetiredAt                             *time.Time
}

// ModuleRoleDef is a role a module provides in every tenant; Permissions are
// "resource:action" references of the module.
type ModuleRoleDef struct {
	Module, Slug, DisplayName, Description string
	Permissions                            []string
	UpdatedAt                              time.Time
	RetiredAt                              *time.Time
}

// TenantModule records that a module registered in a tenant and whether the
// access-preserving migration of legacy grants completed.
type TenantModule struct {
	TenantID, Module  string
	FirstRegisteredAt time.Time
	LegacyMigratedAt  *time.Time
}

// Session row.
type Session struct {
	ID, TenantID, UserID string
	SecretHash           []byte
	AMR                  []string
	CreatedAt, LastSeen  time.Time
	ExpiresAt            time.Time
	IPHash, UserAgent    string
	RevokedAt            *time.Time
	RevokedReason        *string
}

// SigningKey row.
type SigningKey struct {
	KID                   string
	PublicKey, PrivateEnc []byte
	State                 string
	CreatedAt             time.Time
	RetiringAt, RetiredAt *time.Time
}

// Invitation row.
type Invitation struct {
	ID, TenantID, Email string
	RoleIDs             []string
	GroupIDs            []string
	FirstName, LastName string
	TokenHash           string
	InvitedBy           *string
	ExpiresAt           time.Time
	AcceptedAt          *time.Time
	RevokedAt           *time.Time
}

// RecoveryRequest row.
type RecoveryRequest struct {
	ID, TenantID, UserID, TokenHash string
	ExpiresAt                       time.Time
	UsedAt                          *time.Time
}

// ClientApplication row.
type ClientApplication struct {
	ClientID, TenantID, DisplayName string
	RedirectURIs                    []string
	Public                          bool
	SecretHash                      *string
}

// OperatorGrant row.
type OperatorGrant struct {
	ID, OperatorUserID, TenantID, Reason string
	GrantedAt, ExpiresAt                 time.Time
	RevokedAt                            *time.Time
}

// Revocation row.
type Revocation struct {
	TS                        time.Time
	Kind, SubjectID, TenantID string
	Reason                    string
}

// AuditRow is one application audit event.
type AuditRow struct {
	TS                      time.Time
	TenantID, EventType     string
	ActorUserID             *string
	ActorKind, ActorService string
	SubjectKind             string
	SubjectID               *string
	Outcome, Reason         string
	OriginIPHash, UserAgent string
	CorrelationID, TraceID  string
	Details                 []byte
}

// OutboxItem is a queued email.
type OutboxItem struct {
	ID, TenantID, Kind, ToEmail string
	PayloadEnc                  []byte
	Attempts                    int
	NextAttemptAt               time.Time
}
