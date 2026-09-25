package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/config"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/ldapdir"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Closed service errors; the text is the API reason. URL, target, CA and
// filter refusals are the ldapdir sentinels (ldapdir.Reason names them).
var (
	ErrValidation        = errors.New("validation_failed")
	ErrInsecureTransport = errors.New("insecure_transport")
	ErrDuplicate         = errors.New("duplicate")
	ErrLimitReached      = errors.New("limit_reached")
	ErrNotFound          = errors.New("not_found")
	ErrRateLimited       = errors.New("rate_limited")
)

// errCredentialRequired refuses reusing a stored bind password for a changed
// destination or trust anchor (url, tls_mode, ca_pem): without it an
// administrator who cannot read the password could re-point the connection at
// a server they control and receive it in the bind (T070). It is a
// validation_failed to callers and audited as a refusal.
var errCredentialRequired = fmt.Errorf("%w: bind password required for a changed target", ErrValidation)

// Connection kinds (attribute presets) and field bounds (contracts §A).
const (
	KindActiveDirectory = "active_directory"
	KindOpenLDAP        = "openldap"
	KindOther           = "other"

	maxNameLen     = 80
	maxURLLen      = 512
	maxDNLen       = 1024
	maxFilterLen   = 4096
	maxPasswordLen = 1024

	defaultSizeLimit   = 500
	defaultTimeLimit   = 15
	ceilingSizeLimit   = 1000
	ceilingTimeSeconds = 60

	subjectKind = "directory_connection"
)

// attrNameRE is an LDAP attribute description without options (RFC 4512
// descr), which also keeps filter metacharacters out of attribute lists.
var attrNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

// presets fill empty mapping fields per kind. "other" has no unique-id
// preset, so its uid attribute must be given.
var presets = map[string]Mapping{
	KindActiveDirectory: {UID: "objectGUID", Email: "mail", DisplayName: "displayName", FirstName: "givenName", LastName: "sn"},
	KindOpenLDAP:        {UID: "entryUUID", Email: "mail", DisplayName: "cn", FirstName: "givenName", LastName: "sn"},
	KindOther:           {Email: "mail"},
}

// Store is what the directory service needs from persistence (directorydb in
// production, memstore in tests). Every method but the AnyTenant lookup is
// tenant scoped.
type Store interface {
	InsertDirectoryConnection(ctx context.Context, c store.DirectoryConnection) error
	GetDirectoryConnection(ctx context.Context, tenantID, id string) (store.DirectoryConnection, error)
	// GetDirectoryConnectionAnyTenant is used only to audit cross-tenant ids.
	GetDirectoryConnectionAnyTenant(ctx context.Context, id string) (store.DirectoryConnection, error)
	ListDirectoryConnections(ctx context.Context, tenantID string) ([]store.DirectoryConnection, error)
	CountDirectoryConnections(ctx context.Context, tenantID string) (int, error)
	UpdateDirectoryConnection(ctx context.Context, c store.DirectoryConnection) error
	SetDirectoryConnectionTest(ctx context.Context, tenantID, id, outcome string, at time.Time) error
	DeleteDirectoryConnection(ctx context.Context, tenantID, id string) error

	// Preview status (search).
	UsersByEmails(ctx context.Context, tenantID string, emails []string) (map[string]store.User, error)
	LinksByUIDs(ctx context.Context, tenantID, connID string, uids []string) (map[string]store.DirectoryLink, error)
	User(ctx context.Context, tenantID, id string) (store.User, error)

	// Atomic runs fn in one transaction under a tenant scope; fn receives
	// an ImportTx (one per imported entry).
	Atomic(ctx context.Context, scope store.Scope, fn func(tx any) error) error
}

// Deps wires the service.
type Deps struct {
	Store     Store
	Directory ldapdir.Directory
	Envelope  *crypto.Envelope
	Policy    *ldapdir.TargetPolicy
	Config    config.Directory
	Cache     *cache.Cache
	Audit     *audit.Writer
	Now       func() time.Time // defaults to time.Now
}

// Service manages a tenant's directory connections.
type Service struct {
	d Deps
}

// New builds the service.
func New(d Deps) *Service { //nolint:gocritic // Deps by value is the wiring signature (T024/T025)
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Service{d: d}
}

// Mapping names the directory attributes read for each profile field.
type Mapping struct {
	UID         string `json:"uid"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
}

// Input is a create or (partial) update. A nil field means "default" on
// create and "keep" on update. BindPassword is write-only.
type Input struct {
	Name             *string  `json:"name,omitempty"`
	Kind             *string  `json:"kind,omitempty"`
	URL              *string  `json:"url,omitempty"`
	TLSMode          *string  `json:"tls_mode,omitempty"`
	AllowTLS12       *bool    `json:"allow_tls12,omitempty"`
	CAPEM            *string  `json:"ca_pem,omitempty"` // "" clears (system roots)
	BindDN           *string  `json:"bind_dn,omitempty"`
	BindPassword     *string  `json:"bind_password,omitempty"`
	BaseDN           *string  `json:"base_dn,omitempty"`
	BaseFilter       *string  `json:"base_filter,omitempty"`
	Attributes       *Mapping `json:"attributes,omitempty"`
	SizeLimit        *int     `json:"size_limit,omitempty"`
	TimeLimitSeconds *int     `json:"time_limit_seconds,omitempty"`
}

// LastTest is the outcome of the most recent saved-connection test.
type LastTest struct {
	At      time.Time `json:"at"`
	Outcome string    `json:"outcome"`
}

// View is the DirectoryConnection wire form (contracts §A). It carries no
// password or ciphertext; CAPEM is filled only by Get.
type View struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Kind             string    `json:"kind"`
	URL              string    `json:"url"`
	TLSMode          string    `json:"tls_mode"`
	AllowTLS12       bool      `json:"allow_tls12"`
	CAPEMSet         bool      `json:"ca_pem_set"`
	CAPEM            string    `json:"ca_pem,omitempty"`
	BindDN           string    `json:"bind_dn"`
	BindPasswordSet  bool      `json:"bind_password_set"`
	BaseDN           string    `json:"base_dn"`
	BaseFilter       string    `json:"base_filter"`
	Attributes       Mapping   `json:"attributes"`
	SizeLimit        int       `json:"size_limit"`
	TimeLimitSeconds int       `json:"time_limit_seconds"`
	LastTest         *LastTest `json:"last_test"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Connection is the name the HTTP layer uses for View.
type Connection = View

func view(c *store.DirectoryConnection, withCA bool) View {
	v := View{
		ID: c.ID, Name: c.Name, Kind: c.Kind, URL: c.URL, TLSMode: c.TLSMode, AllowTLS12: c.AllowTLS12,
		CAPEMSet: c.CAPEM != "", BindDN: c.BindDN, BindPasswordSet: len(c.BindPasswordEnc) > 0,
		BaseDN: c.BaseDN, BaseFilter: c.BaseFilter,
		Attributes: Mapping{UID: c.AttrUID, Email: c.AttrEmail, DisplayName: c.AttrDisplayName, FirstName: c.AttrFirstName, LastName: c.AttrLastName},
		SizeLimit:  c.SizeLimit, TimeLimitSeconds: c.TimeLimitSeconds, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
	if withCA {
		v.CAPEM = c.CAPEM
	}
	if c.LastTestAt != nil && c.LastTestOutcome != nil {
		v.LastTest = &LastTest{At: *c.LastTestAt, Outcome: *c.LastTestOutcome}
	}
	return v
}

// TestResult is a connection test outcome (contracts §A). A failing step is
// a result, not an error; Reason is closed vocabulary, never server text.
type TestResult struct {
	OK         bool
	Step       string // connect | tls | bind | search_base; "" on success
	Reason     string // ldapdir.Reason; "" on success
	TLS        *TLSInfo
	DurationMS int64
}

// TLSInfo describes the negotiated TLS session of a successful test.
type TLSInfo struct {
	Version     string `json:"version"` // tls.VersionName
	PeerSubject string `json:"peer_subject"`
}

// MarshalJSON writes an empty step or reason as null (nullable in the
// contract).
func (r TestResult) MarshalJSON() ([]byte, error) {
	null := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	return json.Marshal(struct {
		OK         bool     `json:"ok"`
		Step       *string  `json:"step"`
		Reason     *string  `json:"reason"`
		TLS        *TLSInfo `json:"tls"`
		DurationMS int64    `json:"duration_ms"`
	}{r.OK, null(r.Step), null(r.Reason), r.TLS, r.DurationMS})
}

// UnmarshalJSON reads the wire form (null step/reason → "").
func (r *TestResult) UnmarshalJSON(b []byte) error {
	var w struct {
		OK         bool     `json:"ok"`
		Step       *string  `json:"step"`
		Reason     *string  `json:"reason"`
		TLS        *TLSInfo `json:"tls"`
		DurationMS int64    `json:"duration_ms"`
	}
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*r = TestResult{OK: w.OK, TLS: w.TLS, DurationMS: w.DurationMS}
	if w.Step != nil {
		r.Step = *w.Step
	}
	if w.Reason != nil {
		r.Reason = *w.Reason
	}
	return nil
}

// sealAD is the envelope associated data binding a sealed bind password to
// its tenant and connection.
func sealAD(tenantID, id string) []byte { return []byte("ldap-bind:" + tenantID + ":" + id) }

// List returns the tenant's connections (without the CA PEM).
func (s *Service) List(ctx context.Context, _ tenantctx.Actor, tenantID string) ([]View, error) { //nolint:gocritic // actor by value is the HTTP-facing signature
	rows, err := s.d.Store.ListDirectoryConnections(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(rows))
	for i := range rows {
		out = append(out, view(&rows[i], false))
	}
	return out, nil
}

// Get returns one connection including its CA PEM (public data).
func (s *Service) Get(ctx context.Context, actor tenantctx.Actor, tenantID, id string) (View, error) { //nolint:gocritic // actor by value is the HTTP-facing signature
	c, err := s.lookup(ctx, &actor, tenantID, id)
	if err != nil {
		return View{}, err
	}
	return view(&c, true), nil
}

// Create validates, seals the bind password and stores a new connection. It
// never contacts the directory.
func (s *Service) Create(ctx context.Context, actor tenantctx.Actor, tenantID string, in Input) (View, error) { //nolint:gocritic // Input by value is the HTTP-facing signature
	refuse := func(err error) (View, error) {
		s.refused(audit.DirectoryConnectionCreated, &actor, tenantID, "", err)
		return View{}, err
	}
	if in.Name == nil || in.Kind == nil || in.TLSMode == nil || in.BindDN == nil || in.BaseDN == nil {
		return View{}, ErrValidation
	}
	if in.URL == nil {
		return View{}, ldapdir.ErrInvalidURL
	}
	maxSize, maxTime := s.maxLimits()
	c := store.DirectoryConnection{ID: store.NewID(), TenantID: tenantID,
		SizeLimit: min(defaultSizeLimit, maxSize), TimeLimitSeconds: min(defaultTimeLimit, maxTime)}
	apply(&c, &in)
	if err := s.validate(&c); err != nil {
		return refuse(err)
	}
	if in.BindPassword == nil {
		return View{}, ErrValidation
	}
	enc, err := s.seal(tenantID, c.ID, *in.BindPassword)
	if err != nil {
		return View{}, err
	}
	c.BindPasswordEnc = enc
	if limit := s.d.Config.MaxConnectionsPerTenant; limit > 0 {
		n, err := s.d.Store.CountDirectoryConnections(ctx, tenantID)
		if err != nil {
			return View{}, err
		}
		if n >= limit {
			return refuse(ErrLimitReached)
		}
	}
	if actor.UserID != "" {
		uid := actor.UserID
		c.CreatedBy, c.UpdatedBy = &uid, &uid
	}
	if err := s.d.Store.InsertDirectoryConnection(ctx, c); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return View{}, ErrDuplicate
		}
		return View{}, err
	}
	stored, err := s.d.Store.GetDirectoryConnection(ctx, tenantID, c.ID)
	if err != nil {
		return View{}, err
	}
	s.emit(&audit.Event{Type: audit.DirectoryConnectionCreated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID,
		SubjectKind: subjectKind, SubjectID: c.ID, Outcome: "ok",
		Details: map[string]any{"kind": c.Kind, "tls_mode": c.TLSMode, "ca_pem_set": c.CAPEM != ""}})
	return view(&stored, false), nil
}

// Update applies a partial update. An omitted bind password keeps the
// stored ciphertext; a given one is sealed again under the same associated
// data.
func (s *Service) Update(ctx context.Context, actor tenantctx.Actor, tenantID, id string, in Input) (View, error) { //nolint:gocritic // Input by value is the HTTP-facing signature
	old, err := s.lookup(ctx, &actor, tenantID, id)
	if err != nil {
		return View{}, err
	}
	c := old
	c.BindPasswordEnc = nil // keep, unless a new password is given
	apply(&c, &in)
	if err := s.validate(&c); err != nil {
		s.refused(audit.DirectoryConnectionUpdated, &actor, tenantID, id, err)
		return View{}, err
	}
	if in.BindPassword == nil && targetChanged(&old, &c) {
		s.refused(audit.DirectoryConnectionUpdated, &actor, tenantID, id, errCredentialRequired)
		return View{}, errCredentialRequired
	}
	if in.BindPassword != nil {
		enc, err := s.seal(tenantID, id, *in.BindPassword)
		if err != nil {
			return View{}, err
		}
		c.BindPasswordEnc = enc
	}
	if actor.UserID != "" {
		uid := actor.UserID
		c.UpdatedBy = &uid
	}
	if err := s.d.Store.UpdateDirectoryConnection(ctx, c); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			return View{}, ErrDuplicate
		case errors.Is(err, store.ErrNotFound):
			return View{}, ErrNotFound
		}
		return View{}, err
	}
	stored, err := s.d.Store.GetDirectoryConnection(ctx, tenantID, id)
	if err != nil {
		return View{}, err
	}
	s.emit(&audit.Event{Type: audit.DirectoryConnectionUpdated, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID,
		SubjectKind: subjectKind, SubjectID: id, Outcome: "ok", Details: map[string]any{"fields": changedFields(&old, &c, in.BindPassword != nil)}})
	return view(&stored, false), nil
}

// Remove deletes a connection. Imported users stay; their links lose the
// connection id and keep the connection name.
func (s *Service) Remove(ctx context.Context, actor tenantctx.Actor, tenantID, id string) error { //nolint:gocritic // actor by value is the HTTP-facing signature
	c, err := s.lookup(ctx, &actor, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.d.Store.DeleteDirectoryConnection(ctx, tenantID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	s.emit(&audit.Event{Type: audit.DirectoryConnectionDeleted, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID,
		SubjectKind: subjectKind, SubjectID: id, Outcome: "ok", Details: map[string]any{"kind": c.Kind}})
	return nil
}

// lookup finds a connection in tenantID. An id that exists in another tenant
// is audited as cross_tenant_refused and still reported as not found.
func (s *Service) lookup(ctx context.Context, actor *tenantctx.Actor, tenantID, id string) (store.DirectoryConnection, error) {
	if !tenantctx.ValidTenantID(id) {
		return store.DirectoryConnection{}, ErrNotFound
	}
	c, err := s.d.Store.GetDirectoryConnection(ctx, tenantID, id)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.DirectoryConnection{}, err
	}
	if other, oerr := s.d.Store.GetDirectoryConnectionAnyTenant(ctx, id); oerr == nil && other.TenantID != tenantID {
		s.emit(&audit.Event{Type: audit.CrossTenantRefused, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID,
			Outcome: "refused", Reason: "foreign_directory_connection", SubjectKind: subjectKind, SubjectID: id,
			Details: map[string]any{"target_tenant": other.TenantID}})
	}
	return store.DirectoryConnection{}, ErrNotFound
}

// targetChanged reports whether c points the stored connection old at another
// server or trusts another CA; the stored password may then not be reused.
func targetChanged(old, c *store.DirectoryConnection) bool {
	return old.URL != c.URL || old.TLSMode != c.TLSMode || old.CAPEM != c.CAPEM
}

// apply copies the given input fields onto c (nil = keep).
func apply(c *store.DirectoryConnection, in *Input) {
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	if in.Name != nil {
		c.Name = strings.TrimSpace(*in.Name)
	}
	set(&c.Kind, in.Kind)
	set(&c.URL, in.URL)
	set(&c.TLSMode, in.TLSMode)
	set(&c.CAPEM, in.CAPEM)
	set(&c.BindDN, in.BindDN)
	set(&c.BaseDN, in.BaseDN)
	set(&c.BaseFilter, in.BaseFilter)
	if in.AllowTLS12 != nil {
		c.AllowTLS12 = *in.AllowTLS12
	}
	if m := in.Attributes; m != nil {
		c.AttrUID, c.AttrEmail, c.AttrDisplayName, c.AttrFirstName, c.AttrLastName = m.UID, m.Email, m.DisplayName, m.FirstName, m.LastName
	}
	if in.SizeLimit != nil {
		c.SizeLimit = *in.SizeLimit
	}
	if in.TimeLimitSeconds != nil {
		c.TimeLimitSeconds = *in.TimeLimitSeconds
	}
}

// validate checks the merged row, fills empty attributes from the kind
// preset and canonicalises the base filter. Only closed errors are returned.
func (s *Service) validate(c *store.DirectoryConnection) error {
	if !validName(c.Name) {
		return ErrValidation
	}
	preset, ok := presets[c.Kind]
	if !ok {
		return ErrValidation
	}
	switch c.TLSMode {
	case ldapdir.TLSModeLDAPS, ldapdir.TLSModeStartTLS, ldapdir.TLSModePlain:
	default:
		return ErrValidation
	}
	if err := s.checkTarget(c.URL, c.TLSMode); err != nil {
		return err
	}
	if c.CAPEM != "" {
		if _, err := ldapdir.ParseCA(c.CAPEM); err != nil {
			return ldapdir.ErrInvalidCA
		}
	}
	if !validDN(c.BindDN) || !validDN(c.BaseDN) {
		return ErrValidation
	}
	filter, err := canonicalFilter(c.BaseFilter)
	if err != nil {
		return err
	}
	c.BaseFilter = filter
	if maxSize, maxTime := s.maxLimits(); c.SizeLimit < 1 || c.SizeLimit > maxSize || c.TimeLimitSeconds < 1 || c.TimeLimitSeconds > maxTime {
		return ErrValidation
	}
	return fillMapping(c, &preset)
}

// checkTarget runs the save-time target policy and the scheme/TLS-mode
// pairing, then refuses plaintext unless this is a development deployment
// with the explicit opt-out.
func (s *Service) checkTarget(rawURL, mode string) error {
	if len(rawURL) > maxURLLen {
		return ldapdir.ErrInvalidURL
	}
	ep, err := s.d.Policy.CheckURL(rawURL)
	if err != nil {
		if errors.Is(err, ldapdir.ErrTargetRefused) {
			return ldapdir.ErrTargetRefused
		}
		return ldapdir.ErrInvalidURL
	}
	if (ep.Scheme == "ldaps") != (mode == ldapdir.TLSModeLDAPS) {
		return ldapdir.ErrInvalidURL
	}
	if mode == ldapdir.TLSModePlain && !s.d.Config.AllowPlaintext {
		return ErrInsecureTransport
	}
	return nil
}

// usable refuses a stored plain connection that this deployment no longer
// allows (directory.allow_plaintext withdrawn) before its
// password is unsealed: the save-time check alone would keep binding in clear
// text after the setting changed (T070).
func (s *Service) usable(c *store.DirectoryConnection) error {
	if c.TLSMode == ldapdir.TLSModePlain && !s.d.Config.AllowPlaintext {
		return ErrInsecureTransport
	}
	return nil
}

// maxLimits returns the deployment's per-search maxima, bounded by the API
// ceilings (1000 entries, 60 s).
func (s *Service) maxLimits() (size, seconds int) {
	size = s.d.Config.MaxSizeLimit
	if size <= 0 || size > ceilingSizeLimit {
		size = ceilingSizeLimit
	}
	seconds = int(s.d.Config.MaxTimeLimit / time.Second)
	if seconds <= 0 || seconds > ceilingTimeSeconds {
		seconds = ceilingTimeSeconds
	}
	return size, seconds
}

// fillMapping fills empty attributes from the kind preset and checks every
// name; the unique-id and e-mail attributes are required.
func fillMapping(c *store.DirectoryConnection, preset *Mapping) error {
	for _, f := range []struct {
		dst *string
		def string
	}{
		{&c.AttrUID, preset.UID}, {&c.AttrEmail, preset.Email}, {&c.AttrDisplayName, preset.DisplayName},
		{&c.AttrFirstName, preset.FirstName}, {&c.AttrLastName, preset.LastName},
	} {
		if *f.dst == "" {
			*f.dst = f.def
		}
		if *f.dst != "" && !attrNameRE.MatchString(*f.dst) {
			return ErrValidation
		}
	}
	if c.AttrUID == "" || c.AttrEmail == "" {
		return ErrValidation
	}
	return nil
}

// seal checks and encrypts a bind password under ldap-bind:<tenant>:<id>.
// An empty or blank password (anonymous bind) is refused.
func (s *Service) seal(tenantID, id, pw string) ([]byte, error) {
	if strings.TrimSpace(pw) == "" || len(pw) > maxPasswordLen {
		return nil, ErrValidation
	}
	buf := []byte(pw)
	defer clear(buf)
	enc, err := s.d.Envelope.Encrypt(buf, sealAD(tenantID, id))
	if err != nil {
		return nil, errors.New("directory: sealing the bind password failed")
	}
	return enc, nil
}

func validName(n string) bool {
	if n == "" || utf8.RuneCountInString(n) > maxNameLen || !utf8.ValidString(n) {
		return false
	}
	return strings.IndexFunc(n, unicode.IsControl) < 0
}

// validDN accepts a non-empty, well-formed DN (the root DSE "" is refused)
// whose every RDN component has a type and a value.
func validDN(dn string) bool {
	if strings.TrimSpace(dn) == "" || len(dn) > maxDNLen {
		return false
	}
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 {
		return false
	}
	for _, rdn := range parsed.RDNs {
		if len(rdn.Attributes) == 0 {
			return false
		}
		for _, a := range rdn.Attributes {
			if a.Type == "" || a.Value == "" {
				return false
			}
		}
	}
	return true
}

// canonicalFilter checks a base filter with the same policy as a search's
// user filter (length, depth, components, attribute names and matching rules) and
// returns its canonical form; "" (no base filter) stays "". A filter saved
// with the bare compiler would pass here and then fail every search (T070).
func canonicalFilter(f string) (string, error) {
	if strings.TrimSpace(f) == "" {
		return "", nil
	}
	if len(f) > maxFilterLen {
		return "", ldapdir.ErrInvalidFilter
	}
	c, err := ldapdir.CompileUserFilter(f)
	if err != nil {
		return "", ldapdir.ErrInvalidFilter
	}
	return c.String(), nil
}

// changedFields names (never values) the fields an update changed.
func changedFields(old, c *store.DirectoryConnection, credential bool) []string {
	var out []string
	add := func(changed bool, name string) {
		if changed {
			out = append(out, name)
		}
	}
	add(old.Name != c.Name, "name")
	add(old.Kind != c.Kind, "kind")
	add(old.URL != c.URL, "url")
	add(old.TLSMode != c.TLSMode, "tls_mode")
	add(old.AllowTLS12 != c.AllowTLS12, "allow_tls12")
	add(old.CAPEM != c.CAPEM, "ca_pem")
	add(old.BindDN != c.BindDN, "bind_dn")
	add(credential, "bind_credential")
	add(old.BaseDN != c.BaseDN, "base_dn")
	add(old.BaseFilter != c.BaseFilter, "base_filter")
	add(old.AttrUID != c.AttrUID || old.AttrEmail != c.AttrEmail || old.AttrDisplayName != c.AttrDisplayName ||
		old.AttrFirstName != c.AttrFirstName || old.AttrLastName != c.AttrLastName, "attributes")
	add(old.SizeLimit != c.SizeLimit, "size_limit")
	add(old.TimeLimitSeconds != c.TimeLimitSeconds, "time_limit_seconds")
	if out == nil {
		out = []string{}
	}
	return out
}

// refused audits policy refusals (D14): plaintext, a refused target, the
// per-tenant cap and a stored password offered to a changed target. Plain input mistakes are not audited.
func (s *Service) refused(t audit.EventType, actor *tenantctx.Actor, tenantID, id string, err error) {
	var reason string
	switch {
	case errors.Is(err, ErrInsecureTransport):
		reason = ErrInsecureTransport.Error()
	case errors.Is(err, ldapdir.ErrTargetRefused):
		reason = ldapdir.Reason(err)
	case errors.Is(err, ErrLimitReached):
		reason = ErrLimitReached.Error()
	case errors.Is(err, errCredentialRequired):
		reason = "bind_password_required"
	default:
		return
	}
	e := audit.Event{Type: t, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: reason}
	if id != "" {
		e.SubjectKind, e.SubjectID = subjectKind, id
	}
	s.emit(&e)
}

func (s *Service) emit(e *audit.Event) {
	if s.d.Audit != nil {
		_ = s.d.Audit.Emit(*e)
	}
}
