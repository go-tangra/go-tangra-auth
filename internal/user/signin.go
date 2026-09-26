// Package user implements sign-in: tenant resolution, credential and status
// checks with identical timing and responses for every failure, per-origin
// and per-account rate limits, lockout, attempt records and the MFA hand-off.
package user

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/webauthn"
)

// Refusals (mapped to reasons at the API).
var (
	ErrInvalidCredentials = errors.New("invalid_credentials")
	ErrLocked             = errors.New("locked")
	ErrRateLimited        = errors.New("rate_limited")
	// ErrKeyFlagged: the security key is flagged as possibly cloned.
	ErrKeyFlagged = webauthn.ErrKeyFlagged
)

// Limits for the sliding windows (per FR: per account and per origin).
const (
	IPWindow       = 10 * time.Minute
	IPLimit        = 60
	AccountWindow  = 10 * time.Minute
	AccountLimit   = 20
	ChallengeTTL   = 5 * time.Minute
	ChallengeBytes = 24
)

// Store is what sign-in needs from persistence.
type Store interface {
	TenantBySlug(ctx context.Context, slug string) (store.Tenant, error)
	UserByEmail(ctx context.Context, tenantID, email string) (store.User, error)
	Roles(ctx context.Context, tenantID, userID string) ([]string, error)
	TouchSignin(ctx context.Context, tenantID, userID string) error
	SetPasswordHash(ctx context.Context, tenantID, userID, hash string) error
	Attempt(ctx context.Context, tenantID, userID, emailHash, ipHash, outcome, reason string) error
}

// MFAVerifier checks a second factor; method is "otp" or "recovery".
type MFAVerifier interface {
	Verify(ctx context.Context, tenantID, userID, code string) (method string, err error)
}

// MethodLister lists a user's second-factor methods (implemented by
// *mfa.Service): "webauthn", "totp", "recovery".
type MethodLister interface {
	Methods(ctx context.Context, tenantID, userID string) ([]string, error)
}

// KeyVerifier runs the security-key step of a pending sign-in (implemented by
// *webauthn.Service); ref binds the ceremony to the MFA challenge.
type KeyVerifier interface {
	SigninOptions(ctx context.Context, ref, tenantID, userID string) (any, error)
	VerifySignin(ctx context.Context, ref, tenantID, userID string, response []byte) error
}

// Service performs sign-in.
type Service struct {
	st       Store
	cache    *cache.Cache
	audit    *audit.Writer
	sessions *session.Manager
	mfa      MFAVerifier
	methods  MethodLister
	keys     KeyVerifier
	now      func() time.Time
	pad      func(time.Time)
}

// New wires the service; mfa may be nil until enrolment exists.
func New(st Store, c *cache.Cache, a *audit.Writer, sm *session.Manager, mfa MFAVerifier) *Service {
	return &Service{st: st, cache: c, audit: a, sessions: sm, mfa: mfa, now: time.Now, pad: password.Pad}
}

// SetPad overrides the timing pad (tests only).
func (s *Service) SetPad(f func(time.Time)) { s.pad = f }

// SetMFA installs the second-factor verifier after construction.
func (s *Service) SetMFA(v MFAVerifier) { s.mfa = v }

// SetMethods installs the method lister for the mfa_required answer.
func (s *Service) SetMethods(m MethodLister) { s.methods = m }

// SetKeys installs the security-key step (nil: keys are disabled).
func (s *Service) SetKeys(k KeyVerifier) { s.keys = k }

// Input is a sign-in request.
type Input struct {
	TenantSlug, Email, Password string
	IP, UserAgent               string
}

// Result is a successful step.
type Result struct {
	// MFARequired means a challenge must be completed before a session exists.
	MFARequired bool
	Challenge   string
	// MFAMethods lists what the second step offers this user (feature 018).
	MFAMethods []string
	// Session and Secret are set once signed in.
	Session store.Session
	Secret  string
	Roles   []string
	// MFASetupRequired reports that the tenant policy demands a factor the
	// user has not enrolled yet.
	MFASetupRequired bool
}

type challenge struct {
	TenantID, UserID, IPHash, UserAgent string
	Roles                               []string
	Operator                            bool
	Policy                              tenant.Policy
}

// HashIP / HashEmail derive the stored pseudonyms.
func HashIP(ip string) string { return crypto.HashToken("ip:" + ip) }
func HashEmail(email string) string {
	return crypto.HashToken("email:" + strings.ToLower(strings.TrimSpace(email)))
}

// Start performs step one. Every refusal except lockout and rate limiting is
// ErrInvalidCredentials and takes the same time.
func (s *Service) Start(ctx context.Context, in Input) (Result, error) {
	start := s.now()
	defer s.pad(start)
	email := strings.ToLower(strings.TrimSpace(in.Email))
	ipHash, emailHash := HashIP(in.IP), HashEmail(email)
	if n, err := s.cache.Count(ctx, cache.RateKey("signin_ip", ipHash), IPWindow); err == nil && n > IPLimit {
		s.attempt(ctx, "", "", emailHash, ipHash, "refused", "rate_limited")
		return Result{}, ErrRateLimited
	}
	// No tenant given: take it from the e-mail domain. An underivable or
	// unknown tenant is the same refusal as any other failure (no oracle).
	if strings.TrimSpace(in.TenantSlug) == "" {
		in.TenantSlug, _ = tenant.SlugFromEmail(email)
	}
	slug, err := tenant.ParseSlug(in.TenantSlug)
	var t store.Tenant
	var u store.User
	known := false
	if err == nil {
		if t, err = s.st.TenantBySlug(ctx, slug); err == nil {
			if u, err = s.st.UserByEmail(ctx, t.ID, email); err == nil {
				// An imported account is indistinguishable from a
				// non-existent one: no lockout, no locked oracle (SR-006).
				if u.Status == "imported" {
					u = store.User{}
				} else {
					known = true
				}
			}
		}
	}
	if n, err := s.cache.Count(ctx, cache.RateKey("signin_acct", t.ID+":"+emailHash), AccountWindow); err == nil && n > AccountLimit {
		s.attempt(ctx, t.ID, u.ID, emailHash, ipHash, "refused", "rate_limited")
		return Result{}, ErrRateLimited
	}
	if known {
		if locked, _ := s.cache.Locked(ctx, u.ID); locked {
			s.attempt(ctx, t.ID, u.ID, emailHash, ipHash, "refused", "locked")
			s.emit(audit.Event{Type: audit.SigninFailed, TenantID: t.ID, ActorKind: "user", ActorUserID: u.ID, Outcome: "refused", Reason: "locked", OriginIPHash: ipHash, UserAgent: in.UserAgent})
			return Result{}, ErrLocked
		}
	}
	hash := ""
	if known && u.PasswordHash != nil {
		hash = *u.PasswordHash
	}
	ok, rehash := password.Verify(in.Password, hash)
	pol := tenant.DefaultPolicy()
	if known {
		pol, _ = tenant.ParsePolicy(t.Policy, t.Kind == "platform")
	}
	switch {
	case !known:
		s.attempt(ctx, t.ID, "", emailHash, ipHash, "refused", "unknown_account")
		if t.ID != "" {
			s.emit(audit.Event{Type: audit.SigninFailed, TenantID: t.ID, ActorKind: "user", Outcome: "refused", Reason: "unknown_account", OriginIPHash: ipHash, UserAgent: in.UserAgent})
		}
		return Result{}, ErrInvalidCredentials
	case !ok:
		return Result{}, s.failure(ctx, t, u, pol, emailHash, ipHash, in.UserAgent, "wrong_password")
	case t.Status != "active":
		return Result{}, s.failure(ctx, t, u, pol, emailHash, ipHash, in.UserAgent, "tenant_suspended")
	case u.Status != "active":
		return Result{}, s.failure(ctx, t, u, pol, emailHash, ipHash, in.UserAgent, "user_"+u.Status)
	}
	_ = s.cache.KV().Del(ctx, cache.RateKey("fail", u.ID))
	if rehash {
		if h, err := password.Hash(in.Password); err == nil {
			_ = s.st.SetPasswordHash(ctx, t.ID, u.ID, h)
		}
	}
	roles, err := s.st.Roles(ctx, t.ID, u.ID)
	if err != nil {
		return Result{}, err
	}
	if u.MFAEnabled {
		id, err := crypto.RandomToken(ChallengeBytes)
		if err != nil {
			return Result{}, err
		}
		c := challenge{TenantID: t.ID, UserID: u.ID, IPHash: ipHash, UserAgent: in.UserAgent, Roles: roles, Operator: t.Kind == "platform", Policy: pol}
		b, _ := json.Marshal(c)
		if err := s.cache.KV().Set(ctx, cache.ChallengeKey(crypto.HashToken(id)), string(b), ChallengeTTL); err != nil {
			return Result{}, err
		}
		s.attempt(ctx, t.ID, u.ID, emailHash, ipHash, "ok", "mfa_pending")
		return Result{MFARequired: true, Challenge: id, MFAMethods: s.mfaMethods(ctx, t.ID, u.ID)}, nil
	}
	res, err := s.establish(ctx, challenge{TenantID: t.ID, UserID: u.ID, IPHash: ipHash, UserAgent: in.UserAgent, Roles: roles, Operator: t.Kind == "platform", Policy: pol}, []string{"pwd"}, emailHash)
	if err != nil {
		return Result{}, err
	}
	res.MFASetupRequired = pol.MFARequired && !u.MFAEnabled
	return res, nil
}

// mfaMethods lists the user's second-factor methods; when they cannot be
// read every method this instance supports is offered. "webauthn" is dropped
// while security keys are disabled.
func (s *Service) mfaMethods(ctx context.Context, tid, uid string) []string {
	all := []string{"webauthn", "totp", "recovery"}
	if s.methods != nil {
		if m, err := s.methods.Methods(ctx, tid, uid); err == nil {
			all = m
		}
	}
	if s.keys == nil {
		all = slices.DeleteFunc(slices.Clone(all), func(m string) bool { return m == "webauthn" })
	}
	return all
}

// pending loads the MFA challenge of step one; it is not consumed here.
func (s *Service) pending(ctx context.Context, challengeID string) (challenge, string, error) {
	key := cache.ChallengeKey(crypto.HashToken(challengeID))
	raw, ok, err := s.cache.KV().Get(ctx, key)
	if err != nil || !ok || challengeID == "" {
		return challenge{}, "", ErrInvalidCredentials
	}
	var c challenge
	if json.Unmarshal([]byte(raw), &c) != nil {
		return challenge{}, "", ErrInvalidCredentials
	}
	return c, key, nil
}

// CompleteMFA performs step two with a TOTP or recovery code.
func (s *Service) CompleteMFA(ctx context.Context, challengeID, code, ip, ua string) (Result, error) {
	return s.complete(ctx, challengeID, ip, ua, func(c challenge) (string, error) {
		if s.mfa == nil {
			return "", ErrInvalidCredentials
		}
		return s.mfa.Verify(ctx, c.TenantID, c.UserID, code)
	})
}

// WebAuthnOptions returns security-key request options for a pending
// sign-in (the user's usable keys), bound to the challenge and the user.
func (s *Service) WebAuthnOptions(ctx context.Context, challengeID string) (any, error) {
	c, _, err := s.pending(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if locked, _ := s.cache.Locked(ctx, c.UserID); locked {
		return nil, ErrLocked
	}
	if n, err := s.cache.Count(ctx, cache.RateKey("webauthn_options", c.UserID), AccountWindow); err == nil && n > AccountLimit {
		return nil, ErrRateLimited
	}
	if s.keys == nil {
		return nil, ErrInvalidCredentials
	}
	opts, err := s.keys.SigninOptions(ctx, crypto.HashToken(challengeID), c.TenantID, c.UserID)
	if errors.Is(err, webauthn.ErrNoKeys) {
		return nil, ErrInvalidCredentials
	}
	return opts, err
}

// CompleteWebAuthn performs step two with a security-key assertion. A
// failure counts toward the same lockout as a wrong code; a key flagged as
// possibly cloned is ErrKeyFlagged. Success records amr ["pwd","hwk"].
func (s *Service) CompleteWebAuthn(ctx context.Context, challengeID string, response []byte, ip, ua string) (Result, error) {
	return s.complete(ctx, challengeID, ip, ua, func(c challenge) (string, error) {
		if s.keys == nil {
			return "", ErrInvalidCredentials
		}
		if err := s.keys.VerifySignin(ctx, crypto.HashToken(challengeID), c.TenantID, c.UserID, response); err != nil {
			return "", err
		}
		return "hwk", nil
	})
}

// complete runs step two: lockout check, verification, the shared failure
// counter and lockout, and the session on success (the challenge is single
// use).
func (s *Service) complete(ctx context.Context, challengeID, ip, ua string, verify func(challenge) (string, error)) (Result, error) {
	start := s.now()
	defer s.pad(start)
	c, key, err := s.pending(ctx, challengeID)
	if err != nil {
		return Result{}, err
	}
	if locked, _ := s.cache.Locked(ctx, c.UserID); locked {
		return Result{}, ErrLocked
	}
	method, err := verify(c)
	if err != nil {
		n, _ := s.cache.Count(ctx, cache.RateKey("fail", c.UserID), c.Policy.LockoutDuration.D())
		reason := "mfa_failed"
		if n >= int64(c.Policy.LockoutThreshold) {
			_ = s.cache.Lock(ctx, c.UserID, c.Policy.LockoutDuration.D())
			_ = s.cache.KV().Del(ctx, key)
			reason = "locked"
			s.emit(audit.Event{Type: audit.Lockout, TenantID: c.TenantID, ActorKind: "user", ActorUserID: c.UserID, Outcome: "refused", Reason: "mfa_failures", OriginIPHash: HashIP(ip), UserAgent: ua})
		}
		s.attempt(ctx, c.TenantID, c.UserID, "", HashIP(ip), "refused", reason)
		s.emit(audit.Event{Type: audit.SigninFailed, TenantID: c.TenantID, ActorKind: "user", ActorUserID: c.UserID, Outcome: "refused", Reason: reason, OriginIPHash: HashIP(ip), UserAgent: ua})
		if errors.Is(err, ErrKeyFlagged) {
			return Result{}, ErrKeyFlagged
		}
		return Result{}, ErrInvalidCredentials
	}
	_ = s.cache.KV().Del(ctx, key)
	_ = s.cache.KV().Del(ctx, cache.RateKey("fail", c.UserID))
	c.IPHash, c.UserAgent = HashIP(ip), ua
	return s.establish(ctx, c, []string{"pwd", method}, "")
}

func (s *Service) establish(ctx context.Context, c challenge, amr []string, emailHash string) (Result, error) {
	sess, secret, err := s.sessions.Create(ctx, session.CreateParams{TenantID: c.TenantID, UserID: c.UserID, Roles: c.Roles, AMR: amr, Operator: c.Operator, IPHash: c.IPHash, UserAgent: c.UserAgent, Policy: c.Policy})
	if err != nil {
		return Result{}, err
	}
	_ = s.st.TouchSignin(ctx, c.TenantID, c.UserID)
	s.attempt(ctx, c.TenantID, c.UserID, emailHash, c.IPHash, "ok", "")
	s.emit(audit.Event{Type: audit.SigninOK, TenantID: c.TenantID, ActorKind: "user", ActorUserID: c.UserID, SubjectKind: "session", SubjectID: sess.ID, Outcome: "ok", OriginIPHash: c.IPHash, UserAgent: c.UserAgent,
		Details: map[string]any{"amr": amr}})
	return Result{Session: sess, Secret: secret, Roles: c.Roles}, nil
}

// failure records a refused attempt for a known account and applies lockout.
func (s *Service) failure(ctx context.Context, t store.Tenant, u store.User, pol tenant.Policy, emailHash, ipHash, ua, reason string) error {
	n, _ := s.cache.Count(ctx, cache.RateKey("fail", u.ID), pol.LockoutDuration.D())
	if n >= int64(pol.LockoutThreshold) {
		_ = s.cache.Lock(ctx, u.ID, pol.LockoutDuration.D())
		s.emit(audit.Event{Type: audit.Lockout, TenantID: t.ID, ActorKind: "user", ActorUserID: u.ID, Outcome: "refused", Reason: "threshold", OriginIPHash: ipHash, UserAgent: ua,
			Details: map[string]any{"failures": n, "duration": pol.LockoutDuration.D().String()}})
		s.attempt(ctx, t.ID, u.ID, emailHash, ipHash, "refused", "locked")
		s.emit(audit.Event{Type: audit.SigninFailed, TenantID: t.ID, ActorKind: "user", ActorUserID: u.ID, Outcome: "refused", Reason: reason, OriginIPHash: ipHash, UserAgent: ua})
		return ErrInvalidCredentials
	}
	s.attempt(ctx, t.ID, u.ID, emailHash, ipHash, "refused", reason)
	s.emit(audit.Event{Type: audit.SigninFailed, TenantID: t.ID, ActorKind: "user", ActorUserID: u.ID, Outcome: "refused", Reason: reason, OriginIPHash: ipHash, UserAgent: ua})
	return ErrInvalidCredentials
}

func (s *Service) attempt(ctx context.Context, tid, uid, emailHash, ipHash, outcome, reason string) {
	_ = s.st.Attempt(ctx, tid, uid, emailHash, ipHash, outcome, reason)
}

func (s *Service) emit(e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Emit(e)
	}
}
