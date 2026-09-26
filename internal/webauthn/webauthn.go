// Package webauthn implements security keys as a second factor (feature 018):
// the relying party from configuration, registration and assertion
// ceremonies over github.com/go-webauthn/webauthn, single-use ceremony
// records in Valkey bound to user and purpose, key limits and names, clone
// detection, and removal re-confirmed by a current factor. Recovery codes,
// the "asks for a second step" flag and the last-factor rule are shared with
// the authenticator app through Factors (internal/mfa).
package webauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/mfa"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Refusals (mapped to reasons at the API).
var (
	ErrInvalidName        = errors.New("invalid_name")
	ErrNameTaken          = errors.New("name_taken")
	ErrKeyLimit           = errors.New("key_limit")
	ErrAlreadyRegistered  = errors.New("already_registered")
	ErrRegistrationFailed = errors.New("registration_failed")
	ErrAssertionFailed    = errors.New("assertion_failed")
	ErrKeyFlagged         = errors.New("key_flagged")
	ErrNoKeys             = errors.New("no_keys")
	ErrTooLarge           = errors.New("response_too_large")
	ErrConfirmationFailed = errors.New("confirmation_failed")
	ErrLastFactor         = errors.New("last_factor_required")
	ErrLocked             = errors.New("locked")
	ErrNotFound           = store.ErrNotFound
)

// Limits (spec FR-001, FR-002; research D10).
const (
	MaxKeys          = 10
	MaxNameRunes     = 64
	MaxResponseBytes = 64 << 10
	MinCredentialID  = 16
	MaxCredentialID  = 1023
	MaxPublicKey     = 2048
	MaxTransports    = 8
	handleBytes      = 32
)

// Ceremony purposes (cache key segment and record field).
const (
	purposeRegister = "reg"
	purposeSignin   = "signin"
	purposeStepUp   = "stepup"
)

// Store is the persistence the service needs.
type Store interface {
	User(ctx context.Context, tenantID, userID string) (store.User, error)
	Tenant(ctx context.Context, tenantID string) (store.Tenant, error)
	WebAuthnHandle(ctx context.Context, tenantID, userID string) ([]byte, error)
	EnsureWebAuthnHandle(ctx context.Context, tenantID, userID string, candidate []byte) ([]byte, error)
	ListWebAuthnCredentials(ctx context.Context, tenantID, userID string) ([]store.WebAuthnCredential, error)
	InsertWebAuthnCredential(ctx context.Context, c store.WebAuthnCredential) error
	RenameWebAuthnCredential(ctx context.Context, tenantID, userID, id, name string) error
	DeleteWebAuthnCredential(ctx context.Context, tenantID, userID, id string) error
	UpdateWebAuthnUse(ctx context.Context, tenantID, id string, signCount int64, backupState bool) error
	FlagWebAuthnClone(ctx context.Context, tenantID, id string) error
}

// Factors is the second-factor state shared with the authenticator app
// (implemented by *mfa.Service).
type Factors interface {
	Verify(ctx context.Context, tenantID, userID, code string) (string, error)
	KeyAdded(ctx context.Context, actor tenantctx.Actor) ([]string, error)
	KeyRemoved(ctx context.Context, actor tenantctx.Actor) error
	GuardRemoval(ctx context.Context, tenantID, userID, keyID string) error
}

// Config is the relying party (config.RelyingParty).
type Config struct {
	RPID             string
	Origins          []string
	DisplayName      string
	UserVerification string // preferred | required
	Timeout          time.Duration
}

// Service runs the ceremonies.
type Service struct {
	st      Store
	factors Factors
	cache   *cache.Cache
	audit   *audit.Writer
	rp      *wa.WebAuthn
	uv      protocol.UserVerificationRequirement
	ttl     time.Duration
}

// New validates the relying party and wires the service.
func New(cfg Config, st Store, f Factors, c *cache.Cache, a *audit.Writer) (*Service, error) {
	uv := protocol.VerificationPreferred
	if cfg.UserVerification == "required" {
		uv = protocol.VerificationRequired
	}
	t := wa.TimeoutConfig{Enforce: true, Timeout: cfg.Timeout, TimeoutUVD: cfg.Timeout}
	rp, err := wa.New(&wa.Config{RPID: cfg.RPID, RPDisplayName: cfg.DisplayName, RPOrigins: cfg.Origins,
		AttestationPreference:  protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementDiscouraged, UserVerification: uv},
		Timeouts:               wa.TimeoutsConfig{Login: t, Registration: t}})
	if err != nil {
		return nil, err
	}
	return &Service{st: st, factors: f, cache: c, audit: a, rp: rp, uv: uv, ttl: cfg.Timeout}, nil
}

// ParseCreation parses a registration response (PublicKeyCredential.toJSON())
// after a size check; malformed input is an error, never a panic (fuzzed).
func ParseCreation(b []byte) (*protocol.ParsedCredentialCreationData, error) {
	if len(b) > MaxResponseBytes {
		return nil, ErrTooLarge
	}
	return protocol.ParseCredentialCreationResponseBytes(b)
}

// ParseAssertion parses an assertion response after a size check (fuzzed).
func ParseAssertion(b []byte) (*protocol.ParsedCredentialAssertionData, error) {
	if len(b) > MaxResponseBytes {
		return nil, ErrTooLarge
	}
	return protocol.ParseCredentialRequestResponseBytes(b)
}

// NormalizeName trims a key name and checks 1–64 printable characters.
func NormalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	n := utf8.RuneCountInString(name)
	if n == 0 || n > MaxNameRunes || !utf8.ValidString(name) || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", ErrInvalidName
	}
	return name, nil
}

// user adapts a user and keys to the library's User.
type user struct {
	handle      []byte
	name, label string
	creds       []wa.Credential
}

func (u user) WebAuthnID() []byte                   { return u.handle }
func (u user) WebAuthnName() string                 { return u.name }
func (u user) WebAuthnDisplayName() string          { return u.label }
func (u user) WebAuthnCredentials() []wa.Credential { return u.creds }

func newUser(u store.User, handle []byte, keys []store.WebAuthnCredential) user {
	label := u.DisplayName
	if label == "" {
		label = u.Email
	}
	out := user{handle: handle, name: u.Email, label: label}
	for _, k := range keys {
		out.creds = append(out.creds, credential(k))
	}
	return out
}

func credential(k store.WebAuthnCredential) wa.Credential { //nolint:gocritic // row value
	tr := make([]protocol.AuthenticatorTransport, 0, len(k.Transports))
	for _, t := range k.Transports {
		tr = append(tr, protocol.AuthenticatorTransport(t))
	}
	return wa.Credential{ID: k.CredentialID, PublicKey: k.PublicKey, AttestationType: "none", Transport: tr,
		Flags:         wa.CredentialFlags{UserPresent: true, BackupEligible: k.BackupEligible, BackupState: k.BackupState},
		Authenticator: wa.Authenticator{AAGUID: k.AAGUID, SignCount: uint32(k.SignCount)}} // #nosec G115 -- sign_count is CHECKed to uint32 range
}

func usable(keys []store.WebAuthnCredential) []store.WebAuthnCredential {
	var out []store.WebAuthnCredential
	for _, k := range keys {
		if k.CloneFlaggedAt == nil {
			out = append(out, k)
		}
	}
	return out
}

// View is a key as its owner sees it.
func View(k store.WebAuthnCredential) mfa.Key { //nolint:gocritic // row value
	return mfa.Key{ID: k.ID, Name: k.Name, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, Flagged: k.CloneFlaggedAt != nil}
}

// ceremony is the single-use record of a pending ceremony.
type ceremony struct {
	Purpose  string         `json:"purpose"`
	TenantID string         `json:"tenant_id"`
	UserID   string         `json:"user_id"`
	Name     string         `json:"name,omitempty"`
	Session  wa.SessionData `json:"session"`
}

func (s *Service) save(ctx context.Context, subject string, c ceremony) error { //nolint:gocritic // record value
	b, _ := json.Marshal(c)
	return s.cache.KV().Set(ctx, cache.WebAuthnKey(c.Purpose, subject), string(b), s.ttl)
}

// take consumes the record (GETDEL) and checks it belongs to the user and
// the purpose; any mismatch is a missing record.
func (s *Service) take(ctx context.Context, purpose, subject, tenantID, userID string) (ceremony, bool) {
	raw, ok, err := s.cache.KV().GetDel(ctx, cache.WebAuthnKey(purpose, subject))
	var c ceremony
	if err != nil || !ok || json.Unmarshal([]byte(raw), &c) != nil || c.Purpose != purpose || c.TenantID != tenantID || c.UserID != userID {
		return ceremony{}, false
	}
	return c, true
}

// BeginRegistration starts adding a named key: creation options for the
// browser (attestation "none", non-discoverable, user verification per
// configuration, the user's keys excluded).
func (s *Service) BeginRegistration(ctx context.Context, actor tenantctx.Actor, name string) (*protocol.CredentialCreation, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return nil, err
	}
	u, err := s.st.User(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return nil, err
	}
	keys, err := s.st.ListWebAuthnCredentials(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return nil, err
	}
	if len(keys) >= MaxKeys {
		return nil, ErrKeyLimit
	}
	for _, k := range keys {
		if strings.EqualFold(k.Name, name) {
			return nil, ErrNameTaken
		}
	}
	candidate := make([]byte, handleBytes)
	if _, err := io.ReadFull(crypto.Rand(), candidate); err != nil {
		return nil, err
	}
	handle, err := s.st.EnsureWebAuthnHandle(ctx, actor.TenantID, actor.UserID, candidate)
	if err != nil {
		return nil, err
	}
	wu := newUser(u, handle, keys)
	exclude := make([]protocol.CredentialDescriptor, 0, len(wu.creds))
	for _, c := range wu.creds {
		exclude = append(exclude, c.Descriptor())
	}
	creation, sess, err := s.rp.BeginRegistration(wu, wa.WithExclusions(exclude), wa.WithConveyancePreference(protocol.PreferNoAttestation),
		wa.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementDiscouraged, UserVerification: s.uv}))
	if err != nil {
		return nil, err
	}
	if err := s.save(ctx, actor.UserID, ceremony{Purpose: purposeRegister, TenantID: actor.TenantID, UserID: actor.UserID, Name: name, Session: *sess}); err != nil {
		return nil, err
	}
	return creation, nil
}

// Registered is the outcome of a registration: the key and, for the user's
// first factor, recovery codes (shown once).
type Registered struct {
	Key           mfa.Key  `json:"key"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

// FinishRegistration verifies the browser's response against the pending
// ceremony and stores the key.
func (s *Service) FinishRegistration(ctx context.Context, actor tenantctx.Actor, response []byte) (Registered, error) {
	c, ok := s.take(ctx, purposeRegister, actor.UserID, actor.TenantID, actor.UserID)
	if !ok {
		return Registered{}, ErrRegistrationFailed
	}
	parsed, err := ParseCreation(response)
	if err != nil {
		return Registered{}, ErrRegistrationFailed
	}
	u, err := s.st.User(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return Registered{}, err
	}
	handle, err := s.st.WebAuthnHandle(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return Registered{}, err
	}
	keys, err := s.st.ListWebAuthnCredentials(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return Registered{}, err
	}
	cred, err := s.rp.CreateCredential(newUser(u, handle, keys), c.Session, parsed)
	if err != nil {
		return Registered{}, ErrRegistrationFailed
	}
	if n := len(cred.ID); n < MinCredentialID || n > MaxCredentialID || len(cred.PublicKey) > MaxPublicKey || len(cred.Transport) > MaxTransports {
		return Registered{}, ErrRegistrationFailed
	}
	if len(keys) >= MaxKeys {
		return Registered{}, ErrKeyLimit
	}
	row := store.WebAuthnCredential{ID: store.NewID(), TenantID: actor.TenantID, UserID: actor.UserID, CredentialID: cred.ID, PublicKey: cred.PublicKey,
		AAGUID: cred.Authenticator.AAGUID, SignCount: int64(cred.Authenticator.SignCount), BackupEligible: cred.Flags.BackupEligible,
		BackupState: cred.Flags.BackupState, Name: c.Name, Transports: []string{}}
	for _, t := range cred.Transport {
		row.Transports = append(row.Transports, string(t))
	}
	switch err := s.st.InsertWebAuthnCredential(ctx, row); {
	case errors.Is(err, store.ErrCredentialExists):
		return Registered{}, ErrAlreadyRegistered
	case errors.Is(err, store.ErrConflict):
		return Registered{}, ErrNameTaken
	case err != nil:
		return Registered{}, err
	}
	codes, err := s.factors.KeyAdded(ctx, actor)
	if err != nil {
		return Registered{}, err
	}
	aaguid, _ := uuid.FromBytes(cred.Authenticator.AAGUID)
	s.emit(audit.Event{Type: audit.MFAEnrolled, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok",
		SubjectKind: "webauthn_credential", SubjectID: row.ID, Details: map[string]any{"method": "webauthn", "aaguid": aaguid.String()}})
	row.CreatedAt = time.Now().UTC()
	return Registered{Key: View(row), RecoveryCodes: codes}, nil
}

// beginAssertion creates request options for the user's usable keys and
// stores the ceremony under purpose/subject.
func (s *Service) beginAssertion(ctx context.Context, purpose, subject, tenantID, userID string) (*protocol.CredentialAssertion, error) {
	u, err := s.st.User(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	handle, err := s.st.WebAuthnHandle(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	keys, err := s.st.ListWebAuthnCredentials(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	assertion, sess, err := s.rp.BeginLogin(newUser(u, handle, usable(keys)), wa.WithUserVerification(s.uv))
	if err != nil {
		return nil, ErrNoKeys
	}
	if err := s.save(ctx, subject, ceremony{Purpose: purpose, TenantID: tenantID, UserID: userID, Session: *sess}); err != nil {
		return nil, err
	}
	return assertion, nil
}

// finishAssertion verifies an assertion against the consumed ceremony. A key
// flagged as possibly cloned is refused; a signature counter that did not
// increase flags the key, is audited and refused (ErrKeyFlagged). Success
// records the counter, backup state and time of use.
func (s *Service) finishAssertion(ctx context.Context, purpose, subject, tenantID, userID string, response []byte) error {
	c, ok := s.take(ctx, purpose, subject, tenantID, userID)
	if !ok {
		return ErrAssertionFailed
	}
	parsed, err := ParseAssertion(response)
	if err != nil {
		return ErrAssertionFailed
	}
	u, err := s.st.User(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	handle, err := s.st.WebAuthnHandle(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	keys, err := s.st.ListWebAuthnCredentials(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	var key store.WebAuthnCredential
	for _, k := range keys {
		if bytes.Equal(k.CredentialID, parsed.RawID) {
			key = k
		}
	}
	if key.CloneFlaggedAt != nil {
		return ErrKeyFlagged
	}
	cred, err := s.rp.ValidateLogin(newUser(u, handle, usable(keys)), c.Session, parsed)
	if err != nil {
		return ErrAssertionFailed
	}
	if cred.Authenticator.CloneWarning {
		if err := s.st.FlagWebAuthnClone(ctx, tenantID, key.ID); err != nil {
			return err
		}
		s.emit(audit.Event{Type: audit.MFACloneSuspected, TenantID: tenantID, ActorKind: "user", ActorUserID: userID, Outcome: "refused", Reason: "counter_regression",
			SubjectKind: "webauthn_credential", SubjectID: key.ID, Details: map[string]any{"ceremony": purpose}})
		return ErrKeyFlagged
	}
	return s.st.UpdateWebAuthnUse(ctx, tenantID, key.ID, int64(cred.Authenticator.SignCount), cred.Flags.BackupState)
}

// SigninOptions starts the key step of a pending sign-in; ref is the hash of
// the MFA challenge (the ceremony is bound to it and to the user).
func (s *Service) SigninOptions(ctx context.Context, ref, tenantID, userID string) (any, error) {
	return s.beginAssertion(ctx, purposeSignin, ref, tenantID, userID)
}

// VerifySignin completes the key step of a pending sign-in.
func (s *Service) VerifySignin(ctx context.Context, ref, tenantID, userID string, response []byte) error {
	return s.finishAssertion(ctx, purposeSignin, ref, tenantID, userID, response)
}

// StepUpOptions starts a key assertion that confirms a removal.
func (s *Service) StepUpOptions(ctx context.Context, actor tenantctx.Actor) (*protocol.CredentialAssertion, error) {
	return s.beginAssertion(ctx, purposeStepUp, actor.UserID, actor.TenantID, actor.UserID)
}

// Rename gives one of the user's keys a new name.
func (s *Service) Rename(ctx context.Context, actor tenantctx.Actor, id, name string) (mfa.Key, error) {
	name, err := NormalizeName(name)
	if err != nil {
		return mfa.Key{}, err
	}
	switch err := s.st.RenameWebAuthnCredential(ctx, actor.TenantID, actor.UserID, id, name); {
	case errors.Is(err, store.ErrConflict):
		return mfa.Key{}, ErrNameTaken
	case err != nil:
		return mfa.Key{}, err
	}
	keys, err := s.st.ListWebAuthnCredentials(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return mfa.Key{}, err
	}
	for _, k := range keys {
		if k.ID == id {
			return View(k), nil
		}
	}
	return mfa.Key{}, ErrNotFound
}

// Confirmation proves a current factor for a removal: an authenticator or
// recovery code, or a key assertion answering StepUpOptions.
type Confirmation struct {
	Code       string
	Credential []byte
}

// Remove deletes one of the user's keys after confirming a current factor.
// The last usable factor under a required policy is refused before anything
// is consumed; a wrong confirmation counts toward the sign-in lockout.
func (s *Service) Remove(ctx context.Context, actor tenantctx.Actor, id string, conf Confirmation) error {
	switch err := s.factors.GuardRemoval(ctx, actor.TenantID, actor.UserID, id); {
	case errors.Is(err, mfa.ErrRequired):
		return ErrLastFactor
	case err != nil:
		return err
	}
	if locked, _ := s.cache.Locked(ctx, actor.UserID); locked {
		return ErrLocked
	}
	err := ErrConfirmationFailed
	switch {
	case conf.Code != "":
		_, err = s.factors.Verify(ctx, actor.TenantID, actor.UserID, conf.Code)
	case len(conf.Credential) > 0:
		err = s.finishAssertion(ctx, purposeStepUp, actor.UserID, actor.TenantID, actor.UserID, conf.Credential)
	}
	if err != nil {
		s.failed(ctx, actor)
		return ErrConfirmationFailed
	}
	if err := s.st.DeleteWebAuthnCredential(ctx, actor.TenantID, actor.UserID, id); err != nil {
		return err
	}
	if err := s.factors.KeyRemoved(ctx, actor); err != nil {
		return err
	}
	s.emit(audit.Event{Type: audit.MFARemoved, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", Reason: "user",
		SubjectKind: "webauthn_credential", SubjectID: id, Details: map[string]any{"method": "webauthn"}})
	return nil
}

// failed counts a wrong confirmation in the sign-in failure counter and
// locks the account at the tenant threshold, exactly like a wrong code.
func (s *Service) failed(ctx context.Context, actor tenantctx.Actor) {
	pol := tenant.DefaultPolicy()
	if t, err := s.st.Tenant(ctx, actor.TenantID); err == nil {
		if p, err := tenant.ParsePolicy(t.Policy, t.Kind == "platform"); err == nil {
			pol = p
		}
	}
	s.emit(audit.Event{Type: audit.MFARemoved, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: "confirmation_failed",
		Details: map[string]any{"method": "webauthn"}})
	n, _ := s.cache.Count(ctx, cache.RateKey("fail", actor.UserID), pol.LockoutDuration.D())
	if n >= int64(pol.LockoutThreshold) {
		_ = s.cache.Lock(ctx, actor.UserID, pol.LockoutDuration.D())
		s.emit(audit.Event{Type: audit.Lockout, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: "mfa_failures"})
	}
}

func (s *Service) emit(e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Emit(e)
	}
}
