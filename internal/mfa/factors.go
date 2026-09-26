package mfa

import (
	"context"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Second-factor state across kinds (feature 018). A user "asks for a second
// step" (users.mfa_enabled) while an authenticator app or at least one
// security key exists; recovery codes are issued with the first factor of any
// kind and shared by all of them.

// Key is a security key as shown to its owner or an administrator: never the
// credential id or public key.
type Key struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	Flagged    bool       `json:"flagged"`
}

// State is a user's second-factor methods.
type State struct {
	Enabled           bool  `json:"-"` // asks for a second step
	TOTP              bool  `json:"totp"`
	Keys              []Key `json:"keys"`
	RecoveryCodesLeft int   `json:"recovery_codes_left"`
	Required          bool  `json:"required"` // tenant policy
}

// Usable counts the factors that can complete a sign-in: the app and every
// key not flagged as possibly cloned.
func (st State) Usable() int {
	n := 0
	if st.TOTP {
		n++
	}
	for _, k := range st.Keys {
		if !k.Flagged {
			n++
		}
	}
	return n
}

func usableKeys(keys []store.WebAuthnCredential) int {
	n := 0
	for _, k := range keys {
		if k.CloneFlaggedAt == nil {
			n++
		}
	}
	return n
}

// State loads the user's methods, recovery codes and the tenant requirement.
func (s *Service) State(ctx context.Context, tenantID, userID string) (State, error) {
	u, err := s.st.User(ctx, tenantID, userID)
	if err != nil {
		return State{}, err
	}
	t, err := s.st.Tenant(ctx, tenantID)
	if err != nil {
		return State{}, err
	}
	pol, err := tenant.ParsePolicy(t.Policy, t.Kind == "platform")
	if err != nil {
		return State{}, err
	}
	keys, err := s.st.ListWebAuthnCredentials(ctx, tenantID, userID)
	if err != nil {
		return State{}, err
	}
	codes, err := s.st.ListRecoveryCodeHashes(ctx, tenantID, userID)
	if err != nil {
		return State{}, err
	}
	st := State{Enabled: u.MFAEnabled, TOTP: len(u.MFASecretEnc) > 0, Keys: make([]Key, 0, len(keys)), RecoveryCodesLeft: len(codes), Required: pol.MFARequired}
	for _, k := range keys {
		st.Keys = append(st.Keys, Key{ID: k.ID, Name: k.Name, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, Flagged: k.CloneFlaggedAt != nil})
	}
	return st, nil
}

// Methods lists what the second sign-in step can offer, in the order the
// console presents them: "webauthn" (a usable key), "totp", "recovery"
// (unused codes left).
func (s *Service) Methods(ctx context.Context, tenantID, userID string) ([]string, error) {
	st, err := s.State(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, k := range st.Keys {
		if !k.Flagged {
			out = append(out, "webauthn")
			break
		}
	}
	if st.TOTP {
		out = append(out, "totp")
	}
	if st.RecoveryCodesLeft > 0 {
		out = append(out, "recovery")
	}
	return out, nil
}

// KeyAdded is called after a security key was stored. The account asks for
// a second step from now on; when the key is the user's first factor, ten
// fresh recovery codes are returned (shown once), otherwise nil.
func (s *Service) KeyAdded(ctx context.Context, actor tenantctx.Actor) ([]string, error) {
	u, err := s.st.User(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return nil, err
	}
	keys, err := s.st.ListWebAuthnCredentials(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return nil, err
	}
	if !u.MFAEnabled {
		if err := s.st.SetMFA(ctx, actor.TenantID, actor.UserID, true, u.MFASecretEnc); err != nil {
			return nil, err
		}
	}
	if len(u.MFASecretEnc) > 0 || len(keys) > 1 {
		return nil, nil
	}
	return s.regenerate(ctx, actor)
}

// KeyRemoved is called after a security key was deleted: with no factor
// left the account stops asking for a second step and unused recovery codes
// are invalidated (FR-013).
func (s *Service) KeyRemoved(ctx context.Context, actor tenantctx.Actor) error {
	u, err := s.st.User(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return err
	}
	keys, err := s.st.ListWebAuthnCredentials(ctx, actor.TenantID, actor.UserID)
	if err != nil {
		return err
	}
	if len(u.MFASecretEnc) > 0 || len(keys) > 0 {
		return nil
	}
	return s.clear(ctx, actor.TenantID, actor.UserID)
}

// GuardRemoval refuses removing key keyID when it is the user's last usable
// factor and the tenant requires MFA (ErrRequired). A key flagged as
// possibly cloned can always be removed. An unknown key is store.ErrNotFound.
func (s *Service) GuardRemoval(ctx context.Context, tenantID, userID, keyID string) error {
	st, err := s.State(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	for _, k := range st.Keys {
		if k.ID != keyID {
			continue
		}
		if !k.Flagged && st.Required && st.Usable() <= 1 {
			return ErrRequired
		}
		return nil
	}
	return store.ErrNotFound
}
