package ldapdir

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// Server diagnostic text is attacker-influenced: AD echoes the bind DN, some
// servers echo the whole request. It must never reach an error string.
const (
	diagSentinel     = "DIAG-SENTINEL-80090308 LdapErr: DSID-0C09044E data 52e"
	passwordSentinel = "PW-SENTINEL-hunter2"
)

func ldapErr(code uint16, inner error) error { return ldap.NewError(code, inner) }

func netOp(inner error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 636}, Err: inner}
}

// closedSentinels is the whole vocabulary a caller may observe (contracts §C).
var closedSentinels = []error{
	ErrTargetRefused, ErrUnreachable, ErrTimeout, ErrTLS, ErrInvalidCredentials,
	ErrBaseNotFound, ErrDirectory, ErrInvalidFilter, ErrInvalidBase, ErrInvalidURL, ErrInvalidCA,
}

func isClosed(err error) bool {
	for _, s := range closedSentinels {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

// assertSanitised checks the properties every mapped error has: it belongs to
// the closed vocabulary, it drops the go-ldap error (and with it the server's
// diagnostic text and the request packet), and its text carries no secret.
func assertSanitised(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	if !isClosed(err) {
		t.Errorf("error %q (%T) is outside the closed vocabulary", err, err)
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		t.Errorf("error %q still wraps *ldap.Error (diagnostic text / packet reachable)", err)
	}
	msg := err.Error()
	for _, s := range append([]string{diagSentinel, passwordSentinel, "LdapErr", "DSID"}, secrets...) {
		if s != "" && strings.Contains(msg, s) {
			t.Errorf("error text %q contains %q", msg, s)
		}
	}
}

func TestMapErrorResultCodes(t *testing.T) {
	diag := errors.New(diagSentinel + " " + passwordSentinel)
	cases := []struct {
		name string
		in   error
		want error
	}{
		{"49 invalid credentials", ldapErr(ldap.LDAPResultInvalidCredentials, diag), ErrInvalidCredentials},
		{"empty password refused client-side", ldapErr(ldap.ErrorEmptyPassword, diag), ErrInvalidCredentials},
		{"32 no such object", ldapErr(ldap.LDAPResultNoSuchObject, diag), ErrBaseNotFound},
		{"3 time limit exceeded", ldapErr(ldap.LDAPResultTimeLimitExceeded, diag), ErrTimeout},
		{"85 client-side request timeout", ldapErr(ldap.LDAPResultTimeout, diag), ErrTimeout},
		{"wrapped by fmt %w", fmt.Errorf("bind: %w", ldapErr(ldap.LDAPResultInvalidCredentials, diag)), ErrInvalidCredentials},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapError(tc.in)
			if !errors.Is(got, tc.want) {
				t.Fatalf("mapError = %v, want %v", got, tc.want)
			}
			assertSanitised(t, got)
		})
	}
}

// Any other result code becomes ErrDirectory carrying only the numeric code.
func TestMapErrorOtherCodesCarryOnlyTheCode(t *testing.T) {
	diag := errors.New(diagSentinel + " " + passwordSentinel)
	codes := []uint16{
		ldap.LDAPResultOperationsError,             // 1
		ldap.LDAPResultProtocolError,               // 2
		ldap.LDAPResultSizeLimitExceeded,           // 4 outside Search (Search turns it into Truncated)
		ldap.LDAPResultReferral,                    // 10: never followed
		ldap.LDAPResultInappropriateAuthentication, // 48
		ldap.LDAPResultInsufficientAccessRights,    // 50
		ldap.LDAPResultBusy,                        // 51
		ldap.LDAPResultUnavailable,                 // 52
		ldap.LDAPResultUnwillingToPerform,          // 53
		ldap.LDAPResultOther,                       // 80
		ldap.ErrorUnexpectedResponse,               // 205, go-ldap internal
	}
	for _, code := range codes {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			got := mapError(ldapErr(code, diag))
			if !errors.Is(got, ErrDirectory) {
				t.Fatalf("mapError(%d) = %v, want ErrDirectory", code, got)
			}
			for _, other := range []error{ErrInvalidCredentials, ErrBaseNotFound, ErrTimeout, ErrUnreachable, ErrTLS, ErrTargetRefused} {
				if errors.Is(got, other) {
					t.Errorf("mapError(%d) also matches %v", code, other)
				}
			}
			var de *DirectoryError
			if !errors.As(got, &de) {
				t.Fatalf("mapError(%d) = %T, want *DirectoryError", code, got)
			}
			if de.Code != int(code) {
				t.Errorf("Code = %d, want %d", de.Code, code)
			}
			if !strings.Contains(got.Error(), fmt.Sprint(code)) {
				t.Errorf("error text %q does not name the code %d", got, code)
			}
			assertSanitised(t, got)
		})
	}
}

func TestMapErrorTransport(t *testing.T) {
	timeoutOp := netOp(os.ErrDeadlineExceeded)
	cases := []struct {
		name string
		in   error
		want error
	}{
		{"connection refused", ldapErr(ldap.ErrorNetwork, netOp(syscall.ECONNREFUSED)), ErrUnreachable},
		{"host unreachable", ldapErr(ldap.ErrorNetwork, netOp(syscall.EHOSTUNREACH)), ErrUnreachable},
		{"no such host", ldapErr(ldap.ErrorNetwork, netOp(&net.DNSError{Err: "no such host", Name: "ldap.example.test", IsNotFound: true})), ErrUnreachable},
		{"connection closed", ldapErr(ldap.ErrorNetwork, errors.New("ldap: connection closed")), ErrUnreachable},
		{"dial timeout", ldapErr(ldap.ErrorNetwork, timeoutOp), ErrTimeout},
		{"bare net timeout", timeoutOp, ErrTimeout},
		{"context deadline", context.DeadlineExceeded, ErrTimeout},
		{"wrapped context deadline", fmt.Errorf("search: %w", context.DeadlineExceeded), ErrTimeout},
		{"policy refused in Control", ldapErr(ldap.ErrorNetwork, netOp(fmt.Errorf("%w: address", ErrTargetRefused))), ErrTargetRefused},
		{"unknown authority", ldapErr(ldap.ErrorNetwork, x509.UnknownAuthorityError{}), ErrTLS},
		{"hostname mismatch", ldapErr(ldap.ErrorNetwork, x509.HostnameError{Host: "ldap.example.test", Certificate: &x509.Certificate{}}), ErrTLS},
		{"certificate verification", ldapErr(ldap.ErrorNetwork, &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}), ErrTLS},
		{"record header (plaintext peer)", ldapErr(ldap.ErrorNetwork, tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}), ErrTLS},
		{"tls alert", ldapErr(ldap.ErrorNetwork, tls.AlertError(40)), ErrTLS},
		// crypto/tls reports a peer alert (e.g. protocol_version when the server
		// cannot do TLS 1.3) as a *net.OpError with Op "remote error".
		{"remote tls alert", ldapErr(ldap.ErrorNetwork, &net.OpError{Op: "remote error", Err: errors.New("tls: protocol version not supported")}), ErrTLS},
		{"local tls error", ldapErr(ldap.ErrorNetwork, &net.OpError{Op: "local error", Err: errors.New("tls: unexpected message")}), ErrTLS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapError(tc.in)
			if !errors.Is(got, tc.want) {
				t.Fatalf("mapError = %v, want %v", got, tc.want)
			}
			assertSanitised(t, got, "192.0.2.1", "ldap.example.test")
		})
	}
}

func TestMapErrorPassThroughAndUnknown(t *testing.T) {
	if mapError(nil) != nil {
		t.Fatal("mapError(nil) must be nil")
	}
	// Already-closed errors keep their identity.
	for _, s := range closedSentinels {
		if got := mapError(s); !errors.Is(got, s) {
			t.Errorf("mapError(%v) = %v, want identity", s, got)
		}
	}
	de := mapError(ldapErr(ldap.LDAPResultBusy, errors.New(diagSentinel)))
	if got := mapError(de); !errors.Is(got, ErrDirectory) {
		t.Errorf("mapError(DirectoryError) = %v", got)
	}

	// Anything unrecognised is a directory error with no code and no text.
	got := mapError(errors.New("surprise " + diagSentinel + " " + passwordSentinel))
	var d *DirectoryError
	if !errors.As(got, &d) || d.Code != 0 {
		t.Fatalf("unknown error mapped to %#v, want *DirectoryError{Code: 0}", got)
	}
	assertSanitised(t, got)
}

func TestDirectoryError(t *testing.T) {
	err := error(&DirectoryError{Code: 53})
	if !errors.Is(err, ErrDirectory) {
		t.Fatal("DirectoryError must match ErrDirectory")
	}
	if errors.Is(err, ErrTimeout) || errors.Is(err, ErrUnreachable) {
		t.Fatal("DirectoryError must match only ErrDirectory")
	}
	if msg := err.Error(); !strings.HasPrefix(msg, "ldapdir: ") || !strings.Contains(msg, "53") {
		t.Errorf("Error() = %q, want an ldapdir-prefixed text naming code 53", msg)
	}
}

func TestReason(t *testing.T) {
	cases := []struct {
		in   error
		want string
	}{
		{nil, ""},
		{ErrTargetRefused, "target_refused"},
		{fmt.Errorf("%w: port", ErrTargetRefused), "target_refused"},
		{ErrUnreachable, "unreachable"},
		{ErrTimeout, "timeout"},
		{ErrTLS, "tls_failed"},
		{ErrInvalidCredentials, "invalid_credentials"},
		{ErrBaseNotFound, "base_not_found"},
		{ErrDirectory, "directory_error"},
		{&DirectoryError{Code: 80}, "directory_error"},
		{ErrInvalidFilter, "invalid_filter"},
		{ErrInvalidBase, "invalid_base"},
		{ErrInvalidURL, "invalid_url"},
		{ErrInvalidCA, "invalid_ca"},
		{errors.New("anything else"), "directory_error"},
		// Raw go-ldap errors are classified through mapError.
		{ldapErr(ldap.LDAPResultInvalidCredentials, errors.New(diagSentinel)), "invalid_credentials"},
		{ldapErr(ldap.LDAPResultNoSuchObject, errors.New(diagSentinel)), "base_not_found"},
	}
	for _, tc := range cases {
		if got := Reason(tc.in); got != tc.want {
			t.Errorf("Reason(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The sentinels are distinct and their texts are fixed, prefixed and secret-free.
func TestSentinelsDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i, a := range closedSentinels {
		if !strings.HasPrefix(a.Error(), "ldapdir: ") {
			t.Errorf("%q lacks the ldapdir prefix", a)
		}
		if seen[a.Error()] {
			t.Errorf("duplicate sentinel text %q", a)
		}
		seen[a.Error()] = true
		for j, b := range closedSentinels {
			if i != j && errors.Is(a, b) {
				t.Errorf("%v matches %v", a, b)
			}
		}
	}
}
