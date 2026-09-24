package user

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"unicode"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Profile refusals (feature 004).
var (
	ErrInvalidName  = errors.New("invalid_name")
	ErrInvalidPhone = errors.New("invalid_phone")
	ErrForbidden    = errors.New("forbidden")
)

// Limits.
const (
	NameMax      = 100
	LookupMax    = 100
	displayNameM = 100
)

// ProfileStore is the persistence used by Profiles.
type ProfileStore interface {
	User(ctx context.Context, tenantID, id string) (store.User, error)
	UserAnyTenant(ctx context.Context, id string) (store.User, error)
	UpdateProfile(ctx context.Context, tenantID, id string, p store.ProfilePatch) error
	LookupProfiles(ctx context.Context, tenantID string, ids []string) ([]store.PublicProfile, error)
	SearchProfiles(ctx context.Context, tenantID, q string, limit int) ([]store.PublicProfile, error)
	ListActiveMemberIDs(ctx context.Context, tenantID, after string, limit int, ids []string) ([]string, error)
}

// MembersMax bounds one page of ListMembers.
const MembersMax = 1000

// Profiles reads and writes the person-facing part of a user: names, phone and
// the display name. Phone is PII: it is returned only by Get/Update and never
// written to audit or logs.
type Profiles struct {
	st    ProfileStore
	audit *audit.Writer
}

// NewProfiles wires the service.
func NewProfiles(st ProfileStore, a *audit.Writer) *Profiles {
	return &Profiles{st: st, audit: a}
}

// ProfileUpdate is the writable part of a profile. A nil DisplayName keeps the
// derivation rule; a non-nil one sets it explicitly ("" clears the explicit
// value and returns to derivation).
type ProfileUpdate struct {
	FirstName, LastName, Phone string
	DisplayName                *string
}

// ProfileView is what the account page (self) and the admin page see.
type ProfileView struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Phone       string `json:"phone"`
	AvatarURL   string `json:"avatar_url"`
	UpdatedAt   string `json:"updated_at"`
}

// PublicView is what any member of the tenant may see about another.
type PublicView struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
	Email       string `json:"email,omitempty"` // search results only (subject pickers)
}

// SearchMax bounds subject-picker results.
const SearchMax = 20

// ErrQueryTooShort refuses searches under two characters.
var ErrQueryTooShort = errors.New("user: query too short")

var phoneRE = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// NormalizePhone strips spaces, hyphens, dots and parentheses and requires
// E.164; empty clears the field.
func NormalizePhone(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ' || r == '-' || r == '.' || r == '(' || r == ')':
			continue
		case r == '+' || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			return "", ErrInvalidPhone
		}
	}
	out := b.String()
	if !phoneRE.MatchString(out) {
		return "", ErrInvalidPhone
	}
	return out, nil
}

// ValidateName trims and checks a name component (≤ 100 chars, no control characters).
func ValidateName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > NameMax {
		return "", ErrInvalidName
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", ErrInvalidName
		}
	}
	return s, nil
}

// DeriveDisplayName implements FR-011/R8: "First Last", else the previous
// display name, else the email local part.
func DeriveDisplayName(first, last, previous, email string) string {
	if n := strings.TrimSpace(first + " " + last); n != "" {
		return n
	}
	if previous != "" {
		return previous
	}
	local, _, _ := strings.Cut(email, "@")
	return local
}

// userLookup is the part of a store needed to find a user in a tenant.
type userLookup interface {
	User(ctx context.Context, tenantID, id string) (store.User, error)
	UserAnyTenant(ctx context.Context, id string) (store.User, error)
}

// lookupInTenant finds the target in the actor's tenant; a hit in another
// tenant is audited as cross_tenant_refused and reported as not found.
func lookupInTenant(ctx context.Context, st userLookup, emit func(audit.Event), actor tenantctx.Actor, uid string) (store.User, error) {
	u, err := st.User(ctx, actor.TenantID, uid)
	if err == nil {
		return u, nil
	}
	if errors.Is(err, store.ErrNotFound) && tenantctx.ValidTenantID(uid) {
		if other, oerr := st.UserAnyTenant(ctx, uid); oerr == nil && other.TenantID != actor.TenantID {
			emit(audit.Event{Type: audit.CrossTenantRefused, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: "foreign_user",
				SubjectKind: "user", SubjectID: uid, Details: map[string]any{"target_tenant": other.TenantID}})
		}
	}
	return store.User{}, ErrNotFound
}

func (p *Profiles) lookup(ctx context.Context, actor tenantctx.Actor, uid string) (store.User, error) {
	return lookupInTenant(ctx, p.st, p.emit, actor, uid)
}

// mayEdit: the person themselves or a tenant administrator.
func mayEdit(actor tenantctx.Actor, uid string) bool {
	return actor.UserID == uid || actor.IsAdmin() || actor.Kind == tenantctx.KindSystem
}

// Get returns a profile (with phone) to its owner or an administrator.
func (p *Profiles) Get(ctx context.Context, actor tenantctx.Actor, uid string) (ProfileView, error) {
	if !mayEdit(actor, uid) {
		return ProfileView{}, ErrForbidden
	}
	u, err := p.lookup(ctx, actor, uid)
	if err != nil {
		return ProfileView{}, err
	}
	return view(u), nil
}

func view(u store.User) ProfileView {
	v := ProfileView{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, FirstName: u.FirstName, LastName: u.LastName, Phone: u.Phone, AvatarURL: tenantctx.AvatarURL(u.ID, u.AvatarID)}
	if u.ProfileUpdatedAt != nil {
		v.UpdatedAt = u.ProfileUpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return v
}

// Update validates and stores names/phone, derives the display name, and
// audits the changed field names (never the values).
func (p *Profiles) Update(ctx context.Context, actor tenantctx.Actor, uid string, in ProfileUpdate) (ProfileView, error) {
	if !mayEdit(actor, uid) {
		p.emit(audit.Event{Type: audit.ProfileUpdated, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: ErrForbidden.Error(), SubjectKind: "user", SubjectID: uid})
		return ProfileView{}, ErrForbidden
	}
	u, err := p.lookup(ctx, actor, uid)
	if err != nil {
		return ProfileView{}, err
	}
	first, err := ValidateName(in.FirstName)
	if err != nil {
		return ProfileView{}, err
	}
	last, err := ValidateName(in.LastName)
	if err != nil {
		return ProfileView{}, err
	}
	phone, err := NormalizePhone(in.Phone)
	if err != nil {
		return ProfileView{}, err
	}
	patch := store.ProfilePatch{FirstName: first, LastName: last, Phone: phone, DisplayNameExplicit: u.DisplayNameExplicit, DisplayName: u.DisplayName}
	if in.DisplayName != nil {
		dn, err := ValidateName(*in.DisplayName)
		if err != nil {
			return ProfileView{}, err
		}
		patch.DisplayNameExplicit = dn != ""
		patch.DisplayName = dn
	}
	if !patch.DisplayNameExplicit {
		patch.DisplayName = DeriveDisplayName(first, last, "", u.Email)
	}
	var fields []string
	if first != u.FirstName {
		fields = append(fields, "first_name")
	}
	if last != u.LastName {
		fields = append(fields, "last_name")
	}
	if phone != u.Phone {
		fields = append(fields, "phone")
	}
	if patch.DisplayName != u.DisplayName {
		fields = append(fields, "display_name")
	}
	if err := p.st.UpdateProfile(ctx, actor.TenantID, uid, patch); err != nil {
		return ProfileView{}, err
	}
	kind := "self"
	if actor.UserID != uid {
		kind = "admin"
	}
	p.emit(audit.Event{Type: audit.ProfileUpdated, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "user", SubjectID: uid,
		Details: map[string]any{"fields": nonNilStrings(fields), "by": kind}})
	u, err = p.st.User(ctx, actor.TenantID, uid)
	if err != nil {
		return ProfileView{}, err
	}
	return view(u), nil
}

// Lookup returns the public profile of members of the actor's tenant; unknown
// and foreign ids are omitted (uniform: no enumeration signal).
func (p *Profiles) Lookup(ctx context.Context, actor tenantctx.Actor, ids []string) ([]PublicView, error) {
	if len(ids) > LookupMax {
		ids = ids[:LookupMax]
	}
	rows, err := p.st.LookupProfiles(ctx, actor.TenantID, ids)
	if err != nil {
		return nil, err
	}
	out := make([]PublicView, 0, len(rows))
	for _, r := range rows {
		out = append(out, PublicView{ID: r.ID, DisplayName: r.DisplayName, AvatarURL: tenantctx.AvatarURL(r.ID, r.AvatarID)})
	}
	return out, nil
}

// Members pages the ids of the active members of the actor's tenant (or the
// active ones among ids); the next cursor is the last id of a full page.
func (p *Profiles) Members(ctx context.Context, actor tenantctx.Actor, after string, limit int, ids []string) ([]string, string, error) {
	if limit <= 0 || limit > MembersMax {
		limit = MembersMax
	}
	if len(ids) > MembersMax {
		ids = ids[:MembersMax]
	}
	out, err := p.st.ListActiveMemberIDs(ctx, actor.TenantID, after, limit, ids)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(ids) == 0 && len(out) == limit {
		next = out[len(out)-1]
	}
	if out == nil {
		out = []string{}
	}
	return out, next, nil
}

// Search finds active members of the actor's tenant by name or email for
// subject pickers; email is included so the caller can tell namesakes apart.
func (p *Profiles) Search(ctx context.Context, actor tenantctx.Actor, q string) ([]PublicView, error) {
	q = strings.TrimSpace(q)
	if len([]rune(q)) < 2 {
		return nil, ErrQueryTooShort
	}
	if len([]rune(q)) > 100 {
		q = string([]rune(q)[:100])
	}
	rows, err := p.st.SearchProfiles(ctx, actor.TenantID, q, SearchMax)
	if err != nil {
		return nil, err
	}
	out := make([]PublicView, 0, len(rows))
	for _, r := range rows {
		out = append(out, PublicView{ID: r.ID, DisplayName: r.DisplayName, AvatarURL: tenantctx.AvatarURL(r.ID, r.AvatarID), Email: r.Email})
	}
	return out, nil
}

func (p *Profiles) emit(e audit.Event) {
	if p.audit != nil {
		_ = p.audit.Emit(e)
	}
}
