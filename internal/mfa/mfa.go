// Package mfa implements the second factor: TOTP enrolment/confirmation with
// an envelope-encrypted seed, ±1-step verification with counter replay
// protection, single-use recovery codes and policy-aware disabling. Security
// keys (internal/webauthn, feature 018) share the recovery codes, the
// "asks for a second step" flag and the last-factor rule kept here.
package mfa

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Errors.
var (
	ErrInvalidCode = errors.New("invalid_code")
	ErrNotEnrolled = errors.New("not_enrolled")
	ErrRequired    = errors.New("mfa_required")
	ErrNoPending   = errors.New("no_pending_enrolment")
)

// Store is the persistence the service needs.
type Store interface {
	User(ctx context.Context, tenantID, userID string) (store.User, error)
	Tenant(ctx context.Context, tenantID string) (store.Tenant, error)
	SetMFA(ctx context.Context, tenantID, userID string, enabled bool, secretEnc []byte) error
	SetMFACounter(ctx context.Context, tenantID, userID string, counter int64) error
	ReplaceRecoveryCodes(ctx context.Context, tenantID, userID string, hashes []string) error
	ListRecoveryCodeHashes(ctx context.Context, tenantID, userID string) ([]string, error)
	UseRecoveryCode(ctx context.Context, tenantID, userID, hash string) error
	ListWebAuthnCredentials(ctx context.Context, tenantID, userID string) ([]store.WebAuthnCredential, error)
}

// Constants.
const (
	Period        = 30
	Skew          = 1
	EnrolTTL      = 10 * time.Minute
	RecoveryCount = 10
	recoveryAlpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0/O/1/I
)

var opts = totp.ValidateOpts{Period: Period, Skew: Skew, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}

// Service manages second factors.
type Service struct {
	st     Store
	cache  *cache.Cache
	env    *crypto.Envelope
	audit  *audit.Writer
	issuer string // shown in authenticator apps
	now    func() time.Time
}

// New wires the service.
func New(st Store, c *cache.Cache, env *crypto.Envelope, a *audit.Writer, issuer string) *Service {
	return &Service{st: st, cache: c, env: env, audit: a, issuer: issuer, now: time.Now}
}

func seedAD(uid string) []byte { return []byte("mfa:" + uid) }

// Enrolment is what the console shows once.
type Enrolment struct {
	Secret string `json:"secret"` // base32, for manual entry
	URI    string `json:"otpauth_uri"`
}

// Enrol starts enrolment: a new seed sealed in Valkey until confirmed.
func (s *Service) Enrol(ctx context.Context, actor tenantctx.Actor) (Enrolment, error) {
	u, err := s.st.User(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return Enrolment{}, err
	}
	seed := make([]byte, 20)
	if _, err := io.ReadFull(crypto.Rand(), seed); err != nil {
		return Enrolment{}, err
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.issuer, AccountName: u.Email, Period: Period, Secret: seed, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return Enrolment{}, err
	}
	enc, err := s.env.Encrypt([]byte(key.Secret()), seedAD(actor.UserID))
	if err != nil {
		return Enrolment{}, err
	}
	if err := s.cache.KV().Set(ctx, cache.ChallengeKey("enrol:"+actor.UserID), string(enc), EnrolTTL); err != nil {
		return Enrolment{}, err
	}
	return Enrolment{Secret: key.Secret(), URI: key.URL()}, nil
}

// Confirm activates the pending seed with a valid code and returns fresh
// recovery codes (shown once).
func (s *Service) Confirm(ctx context.Context, actor tenantctx.Actor, code string) ([]string, error) {
	raw, ok, err := s.cache.KV().Get(ctx, cache.ChallengeKey("enrol:"+actor.UserID))
	if err != nil || !ok {
		return nil, ErrNoPending
	}
	secret, err := s.env.Decrypt([]byte(raw), seedAD(actor.UserID))
	if err != nil {
		return nil, ErrNoPending
	}
	counter, ok := s.match(string(secret), code)
	if !ok {
		return nil, ErrInvalidCode
	}
	// Security keys already protect the account: the app is a further
	// factor and the existing recovery codes stay (FR-003).
	keys, err := s.st.ListWebAuthnCredentials(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return nil, err
	}
	if err := s.st.SetMFA(ctx, actor.TenantID, actor.UserID, true, []byte(raw)); err != nil {
		return nil, err
	}
	if err := s.st.SetMFACounter(ctx, actor.TenantID, actor.UserID, counter); err != nil {
		return nil, err
	}
	_ = s.cache.KV().Del(ctx, cache.ChallengeKey("enrol:"+actor.UserID))
	var codes []string
	if len(keys) == 0 {
		if codes, err = s.regenerate(ctx, actor); err != nil {
			return nil, err
		}
	}
	s.emit(audit.Event{Type: audit.MFAEnrolled, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok",
		Details: map[string]any{"method": "totp"}})
	return codes, nil
}

// match reports whether code is valid for secret within ±Skew steps and
// returns the counter of the matching step.
func (s *Service) match(secret, code string) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	now := s.now()
	for delta := -Skew; delta <= Skew; delta++ {
		t := now.Add(time.Duration(delta) * Period * time.Second)
		want, err := totp.GenerateCodeCustom(secret, t, opts)
		if err == nil && crypto.ConstantTimeEqual(want, code) {
			return t.Unix() / Period, true
		}
	}
	return 0, false
}

// Verify checks a TOTP or recovery code for sign-in; method is "otp" or "recovery".
func (s *Service) Verify(ctx context.Context, tenantID, userID, code string) (string, error) {
	u, err := s.st.User(ctx, tenantID, userID)
	if err != nil {
		return "", ErrInvalidCode
	}
	if !u.MFAEnabled {
		return "", ErrNotEnrolled
	}
	code = strings.TrimSpace(code)
	if isDigits(code) {
		if len(u.MFASecretEnc) == 0 {
			return "", ErrInvalidCode // security keys only: no authenticator app
		}
		secret, err := s.env.Decrypt(u.MFASecretEnc, seedAD(userID))
		if err != nil {
			return "", err
		}
		counter, ok := s.match(string(secret), code)
		if !ok || counter <= u.MFALastCounter {
			return "", ErrInvalidCode // wrong, or a replay of an already used step
		}
		if err := s.st.SetMFACounter(ctx, tenantID, userID, counter); err != nil {
			return "", err
		}
		return "otp", nil
	}
	norm := NormalizeRecovery(code)
	if norm == "" {
		return "", ErrInvalidCode
	}
	hashes, err := s.st.ListRecoveryCodeHashes(ctx, tenantID, userID)
	if err != nil {
		return "", err
	}
	for _, h := range hashes {
		if ok, _, err := crypto.VerifyPassword(norm, h); err == nil && ok {
			if err := s.st.UseRecoveryCode(ctx, tenantID, userID, h); err != nil {
				return "", ErrInvalidCode
			}
			return "recovery", nil
		}
	}
	return "", ErrInvalidCode
}

// Disable turns the authenticator app off after a valid code. While security
// keys remain the account keeps asking for a second step and keeps its
// recovery codes; as the last factor it is refused when the tenant requires
// MFA.
func (s *Service) Disable(ctx context.Context, actor tenantctx.Actor, code string) error {
	t, err := s.st.Tenant(ctx, actor.TenantID)
	if err != nil {
		return err
	}
	pol, err := tenant.ParsePolicy(t.Policy, t.Kind == "platform")
	if err != nil {
		return err
	}
	keys, err := s.st.ListWebAuthnCredentials(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return err
	}
	if pol.MFARequired && usableKeys(keys) == 0 {
		return ErrRequired
	}
	if _, err := s.Verify(ctx, actor.TenantID, actor.UserID, code); err != nil {
		return err
	}
	if len(keys) > 0 {
		if err := s.st.SetMFA(ctx, actor.TenantID, actor.UserID, true, nil); err != nil {
			return err
		}
	} else if err := s.clear(ctx, actor.TenantID, actor.UserID); err != nil {
		return err
	}
	s.emit(audit.Event{Type: audit.MFARemoved, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok",
		Details: map[string]any{"method": "totp", "reason": "user"}})
	return nil
}

// clear turns the second step off and invalidates unused recovery codes.
func (s *Service) clear(ctx context.Context, tid, uid string) error {
	if err := s.st.SetMFA(ctx, tid, uid, false, nil); err != nil {
		return err
	}
	return s.st.ReplaceRecoveryCodes(ctx, tid, uid, nil)
}

// Regenerate replaces the recovery codes after a valid code.
func (s *Service) Regenerate(ctx context.Context, actor tenantctx.Actor, code string) ([]string, error) {
	if _, err := s.Verify(ctx, actor.TenantID, actor.UserID, code); err != nil {
		return nil, err
	}
	codes, err := s.regenerate(ctx, actor)
	if err != nil {
		return nil, err
	}
	s.emit(audit.Event{Type: audit.RecoveryCodesRegen, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok"})
	return codes, nil
}

func (s *Service) regenerate(ctx context.Context, actor tenantctx.Actor) ([]string, error) {
	codes := make([]string, 0, RecoveryCount)
	hashes := make([]string, 0, RecoveryCount)
	for i := 0; i < RecoveryCount; i++ {
		c, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		h, err := crypto.HashPassword(NormalizeRecovery(c), crypto.DefaultParams)
		if err != nil {
			return nil, err
		}
		codes = append(codes, c)
		hashes = append(hashes, h)
	}
	if err := s.st.ReplaceRecoveryCodes(ctx, actor.TenantID, actor.UserID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

func newRecoveryCode() (string, error) {
	b := make([]byte, 10)
	if _, err := io.ReadFull(crypto.Rand(), b); err != nil {
		return "", err
	}
	var sb strings.Builder
	for i, x := range b {
		if i == 5 {
			sb.WriteByte('-')
		}
		sb.WriteByte(recoveryAlpha[int(x)%len(recoveryAlpha)])
	}
	return sb.String(), nil
}

// NormalizeRecovery canonicalises user input ("abcde-fghjk" → "ABCDEFGHJK");
// anything outside the alphabet or length yields "".
func NormalizeRecovery(code string) string {
	code = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	if len(code) != 10 {
		return ""
	}
	for _, c := range code {
		if !strings.ContainsRune(recoveryAlpha, c) {
			return ""
		}
	}
	return code
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (s *Service) emit(e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Emit(e)
	}
}
