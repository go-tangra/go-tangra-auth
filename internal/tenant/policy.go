package tenant

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Duration marshals as a Go duration string ("8h", "15m").
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// D returns the time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Policy is the per-tenant SecurityPolicy (data-model.md).
type Policy struct {
	SessionLifetime     Duration `json:"session_lifetime"`
	IdleTimeout         Duration `json:"idle_timeout"`
	AccessTokenLifetime Duration `json:"access_token_lifetime"`
	PasswordMinLength   int      `json:"password_min_length"`
	MFARequired         bool     `json:"mfa_required"`
	LockoutThreshold    int      `json:"lockout_threshold"`
	LockoutDuration     Duration `json:"lockout_duration"`
}

// Limits (data-model.md).
const (
	MaxSessionLifetime     = 24 * time.Hour
	MaxAccessTokenLifetime = 15 * time.Minute
	MinPasswordLength      = 8
)

// DefaultPolicy returns the documented defaults.
func DefaultPolicy() Policy {
	return Policy{SessionLifetime: Duration(8 * time.Hour), IdleTimeout: Duration(time.Hour), AccessTokenLifetime: Duration(15 * time.Minute),
		PasswordMinLength: 12, MFARequired: false, LockoutThreshold: 10, LockoutDuration: Duration(15 * time.Minute)}
}

// ErrPolicy is returned for out-of-range values.
var ErrPolicy = errors.New("tenant: invalid policy")

// ParsePolicy decodes a stored/received policy, filling defaults for absent
// fields and validating ranges. Platform tenants always require MFA.
func ParsePolicy(raw []byte, platform bool) (Policy, error) {
	p := DefaultPolicy()
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return Policy{}, fmt.Errorf("%w: %v", ErrPolicy, err)
		}
	}
	if platform {
		p.MFARequired = true
	}
	return p, p.Validate()
}

// Validate checks the documented ranges.
func (p Policy) Validate() error {
	switch {
	case p.SessionLifetime.D() <= 0 || p.SessionLifetime.D() > MaxSessionLifetime:
		return fmt.Errorf("%w: session_lifetime must be within (0, 24h]", ErrPolicy)
	case p.IdleTimeout.D() <= 0 || p.IdleTimeout.D() > p.SessionLifetime.D():
		return fmt.Errorf("%w: idle_timeout must be within (0, session_lifetime]", ErrPolicy)
	case p.AccessTokenLifetime.D() <= 0 || p.AccessTokenLifetime.D() > MaxAccessTokenLifetime:
		return fmt.Errorf("%w: access_token_lifetime must be within (0, 15m]", ErrPolicy)
	case p.PasswordMinLength < MinPasswordLength || p.PasswordMinLength > 256:
		return fmt.Errorf("%w: password_min_length must be within [8, 256]", ErrPolicy)
	case p.LockoutThreshold < 3 || p.LockoutThreshold > 20:
		return fmt.Errorf("%w: lockout_threshold must be within [3, 20]", ErrPolicy)
	case p.LockoutDuration.D() < time.Minute || p.LockoutDuration.D() > time.Hour:
		return fmt.Errorf("%w: lockout_duration must be within [1m, 1h]", ErrPolicy)
	}
	return nil
}

// JSON encodes the policy for storage.
func (p Policy) JSON() []byte {
	b, _ := json.Marshal(p)
	return b
}
