// Package user implements sign-in: tenant resolution, credential and status
// checks with identical timing and responses for every failure, per-origin
// and per-account rate limits, lockout, attempt records and the MFA hand-off.
package user

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
)

// Refusals (mapped to reasons at the API).
var (
	ErrInvalidCredentials = errors.New("invalid_credentials")
	ErrLocked             = errors.New("locked")
	ErrRateLimited        = errors.New("rate_limited")
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

// Service performs sign-in.
type Service struct {
	st       Store
	cache    *cache.Cache
	audit    *audit.Writer
	sessions *session.Manager
	mfa      MFAVerifier
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
		return Result{MFARequired: true, Challenge: id}, nil
	}
	res, err := s.establish(ctx, challenge{TenantID: t.ID, UserID: u.ID, IPHash: ipHash, UserAgent: in.UserAgent, Roles: roles, Operator: t.Kind == "platform", Policy: pol}, []string{"pwd"}, emailHash)
	if err != nil {
		return Result{}, err
	}
	res.MFASetupRequired = pol.MFARequired && !u.MFAEnabled
	return res, nil
}

// CompleteMFA performs step two with a TOTP or recovery code.
func (s *Service) CompleteMFA(ctx context.Context, challengeID, code, ip, ua string) (Result, error) {
	start := s.now()
	defer s.pad(start)
	key := cache.ChallengeKey(crypto.HashToken(challengeID))
	raw, ok, err := s.cache.KV().Get(ctx, key)
	if err != nil || !ok || challengeID == "" {
		return Result{}, ErrInvalidCredentials
	}
	var c challenge
	if json.Unmarshal([]byte(raw), &c) != nil {
		return Result{}, ErrInvalidCredentials
	}
	if locked, _ := s.cache.Locked(ctx, c.UserID); locked {
		return Result{}, ErrLocked
	}
	method := ""
	if s.mfa != nil {
		method, err = s.mfa.Verify(ctx, c.TenantID, c.UserID, code)
	} else {
		err = ErrInvalidCredentials
	}
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
