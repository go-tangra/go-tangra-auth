package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// WebAuthn configures security keys as a second factor (feature 018,
// research D2). Every key is bound to the relying party: by default the host
// of issuer, with the issuer's origin as the only allowed origin.
type WebAuthn struct {
	// Enabled nil = on unless the issuer host is an IP address (browsers
	// refuse IP relying parties).
	Enabled          *bool    `yaml:"enabled"`
	RPID             string   `yaml:"rp_id"`             // default: host of issuer
	Origins          []string `yaml:"origins"`           // default: [origin of issuer]
	DisplayName      string   `yaml:"display_name"`      // default: mfa.issuer
	UserVerification string   `yaml:"user_verification"` // preferred (default) | required
	TimeoutSeconds   int      `yaml:"timeout_seconds"`   // [30, 600], default 300
}

// RelyingParty is the effective WebAuthn relying party.
type RelyingParty struct {
	Enabled          bool
	ID               string
	Origins          []string
	DisplayName      string
	UserVerification string
	Timeout          time.Duration
}

// RelyingParty resolves the webauthn block against issuer and mfa.issuer.
func (c Config) RelyingParty() RelyingParty {
	w := c.WebAuthn
	rp := RelyingParty{ID: w.RPID, Origins: w.Origins, DisplayName: w.DisplayName, UserVerification: w.UserVerification,
		Timeout: time.Duration(w.TimeoutSeconds) * time.Second}
	u, _ := url.Parse(c.Issuer)
	host := ""
	if u != nil {
		host = u.Hostname()
	}
	if rp.ID == "" {
		rp.ID = host
	}
	if len(rp.Origins) == 0 && u != nil {
		o := url.URL{Scheme: u.Scheme, Host: u.Host}
		if u.Port() == "443" {
			o.Host = host
		}
		rp.Origins = []string{o.String()}
	}
	if rp.DisplayName == "" {
		rp.DisplayName = c.MFA.Issuer
	}
	rp.Enabled = net.ParseIP(host) == nil
	if w.Enabled != nil {
		rp.Enabled = *w.Enabled
	}
	return rp
}

func (c Config) validateWebAuthn(prod bool) error {
	w := c.WebAuthn
	if w.UserVerification != "preferred" && w.UserVerification != "required" {
		return errors.New("config: webauthn.user_verification must be preferred or required")
	}
	if w.TimeoutSeconds < 30 || w.TimeoutSeconds > 600 {
		return errors.New("config: webauthn.timeout_seconds must be within [30, 600]")
	}
	if len(w.DisplayName) > 64 {
		return errors.New("config: webauthn.display_name must be at most 64 characters")
	}
	rp := c.RelyingParty()
	if !rp.Enabled {
		return nil
	}
	if net.ParseIP(rp.ID) != nil || strings.ContainsAny(rp.ID, ":/") {
		return fmt.Errorf("config: webauthn.rp_id %q must be a host name (browsers refuse IP addresses and ports)", rp.ID)
	}
	for _, o := range rp.Origins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			return fmt.Errorf("config: webauthn.origins: %q must be an origin (scheme://host[:port])", o)
		}
		switch {
		case u.Scheme == "https":
		case u.Scheme == "http" && u.Hostname() == "localhost" && !prod:
		default:
			return fmt.Errorf("config: webauthn.origins: %q must be https (http://localhost only outside production)", o)
		}
		host := u.Hostname()
		if host != rp.ID && (!strings.HasSuffix(host, "."+rp.ID) || !strings.Contains(rp.ID, ".")) {
			return fmt.Errorf("config: webauthn.rp_id %q must equal or be a registrable parent of the origin host %q", rp.ID, host)
		}
	}
	return nil
}

func (c Config) webAuthnWarnings() []string {
	rp := c.RelyingParty()
	switch {
	case rp.Enabled:
		return nil
	case c.WebAuthn.Enabled == nil:
		return []string{"webauthn: security keys are off because the issuer host " + rp.ID + " is an IP address (set a host name to use keys)"}
	default:
		return []string{"webauthn.enabled is false: security keys cannot be registered or used (users with keys sign in with an authenticator app or recovery code)"}
	}
}
