package ldapdir

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/auth/internal/config"
)

func TestDialerUsesPolicyControl(t *testing.T) {
	p := mustPolicy(t, defaultTargets())
	d := p.Dialer(3 * time.Second)
	if d.Timeout != 3*time.Second || d.Control == nil {
		t.Fatalf("Dialer = %+v, want timeout 3s and a Control hook", d)
	}
	if err := d.Control("tcp", "127.0.0.1:636", nil); !errors.Is(err, ErrTargetRefused) {
		t.Fatalf("Dialer Control(loopback) = %v, want ErrTargetRefused", err)
	}
}

func TestCheckURLHostnameRules(t *testing.T) {
	p := mustPolicy(t, defaultTargets())
	for _, raw := range []string{
		"ldaps://dc_1.corp-a.example.", // trailing dot, '_' label
		"ldaps://DC.Example.COM",       // mixed case
		"ldaps://a." + strings.Repeat("b", 63),
	} {
		if _, err := p.CheckURL(raw); err != nil {
			t.Errorf("CheckURL(%q) = %v, want nil", raw, err)
		}
	}
	for _, raw := range []string{
		"ldaps://2130706433",                           // numeric IP spelling
		"ldaps://010.0.0.1",                            // leading-zero octets
		"ldaps://-dc.example.com",                      // leading hyphen
		"ldaps://dc-.example.com",                      // trailing hyphen
		"ldaps://dc..example.com",                      // empty label
		"ldaps://" + strings.Repeat("a", 64) + ".com",  // label too long
		"ldaps://" + strings.Repeat("a.", 127) + "com", // name too long
		"ldaps://dc!.example.com",                      // sub-delim accepted by url.Parse
		"ldaps://dcé.example.com",                      // non-ASCII (IDNs must be given as punycode)
		"ldaps://dc%21.example.com",                    // escaped punctuation
		"ldaps://[192.0.2.10]",                         // bracketed IPv4
		"ldaps://[2001:db8::10]x",                      // junk after bracket
		"ldaps://[2001:db8::10]:",                      // empty port after bracket
	} {
		if _, err := p.CheckURL(raw); !errors.Is(err, ErrInvalidURL) {
			t.Errorf("CheckURL(%q) = %v, want ErrInvalidURL", raw, err)
		}
	}
}

func TestDenyV6PrefixCoversV4(t *testing.T) {
	p := mustPolicy(t, config.DirectoryTargets{DenyCIDRs: []string{"::ffff:10.0.0.0/104"}, AllowedPorts: []int{636}})
	if err := p.Control("tcp", "10.9.9.9:636", nil); !errors.Is(err, ErrTargetRefused) {
		t.Fatalf("mapped deny prefix: %v, want ErrTargetRefused", err)
	}
	if err := p.Control("tcp", "11.0.0.1:636", nil); err != nil {
		t.Fatalf("outside mapped deny prefix: %v, want nil", err)
	}
	// 0.0.0.0/8 ("this network") is refused with the unspecified address.
	if err := p.Control("tcp", "0.1.2.3:636", nil); !errors.Is(err, ErrTargetRefused) {
		t.Fatalf("0.0.0.0/8: %v, want ErrTargetRefused", err)
	}
}

func TestSplitURLHostUnterminatedBracket(t *testing.T) {
	// url.Parse refuses this first; the check is a second line of defence.
	if _, _, _, err := splitURLHost("[2001:db8::10"); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("splitURLHost = %v, want ErrInvalidURL", err)
	}
}
