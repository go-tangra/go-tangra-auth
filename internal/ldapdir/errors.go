package ldapdir

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"

	"github.com/go-ldap/ldap/v3"
)

// The closed error vocabulary of the LDAP boundary (contracts §C, research
// D9). ErrTargetRefused and ErrInvalidURL live in policy.go, ErrInvalidCA in
// tlsconf.go. Callers see only these values (or *DirectoryError); the go-ldap
// error, the server's diagnostic text and the request packet never escape.
var (
	// ErrUnreachable reports that the directory could not be reached or the
	// connection broke.
	ErrUnreachable = errors.New("ldapdir: directory unreachable")
	// ErrTimeout reports that the dial, the handshake or an operation ran out
	// of time, or that the server hit its own time limit.
	ErrTimeout = errors.New("ldapdir: directory timeout")
	// ErrTLS reports a failed TLS handshake or StartTLS negotiation.
	ErrTLS = errors.New("ldapdir: tls failed")
	// ErrInvalidCredentials reports a refused bind (result code 49) or an
	// empty bind password.
	ErrInvalidCredentials = errors.New("ldapdir: invalid credentials")
	// ErrBaseNotFound reports that the base DN does not exist (result code 32).
	ErrBaseNotFound = errors.New("ldapdir: base not found")
	// ErrDirectory is any other directory failure; *DirectoryError carries
	// the numeric result code.
	ErrDirectory = errors.New("ldapdir: directory error")
	// ErrInvalidFilter reports an LDAP filter that is refused.
	ErrInvalidFilter = errors.New("ldapdir: invalid filter")
	// ErrInvalidBase reports a base DN that is malformed or outside the
	// connection's base.
	ErrInvalidBase = errors.New("ldapdir: invalid base")
)

// DirectoryError is a directory failure outside the named cases. It carries
// only the LDAP result code (0 when there is none), never server text.
type DirectoryError struct {
	Code int
}

func (e *DirectoryError) Error() string {
	if e.Code == 0 {
		return ErrDirectory.Error()
	}
	return ErrDirectory.Error() + " (result code " + strconv.Itoa(e.Code) + ")"
}

// Is makes a *DirectoryError match ErrDirectory.
func (e *DirectoryError) Is(target error) bool { return target == ErrDirectory }

// closedErrors is checked in order; the first match is returned bare so any
// wrapping text is dropped.
var closedErrors = []error{
	ErrTargetRefused, ErrUnreachable, ErrTimeout, ErrTLS, ErrInvalidCredentials,
	ErrBaseNotFound, ErrInvalidFilter, ErrInvalidBase, ErrInvalidURL, ErrInvalidCA,
}

// mapError turns any error from go-ldap, the dialer or crypto/tls into the
// closed vocabulary. The result never wraps the input.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	for _, s := range closedErrors {
		if errors.Is(err, s) {
			return s
		}
	}
	var de *DirectoryError
	if errors.As(err, &de) {
		return &DirectoryError{Code: de.Code}
	}
	if errors.Is(err, ErrDirectory) {
		return ErrDirectory
	}
	if isTLSError(err) {
		return ErrTLS
	}
	var te interface{ Timeout() bool }
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &te) && te.Timeout()) {
		return ErrTimeout
	}
	var le *ldap.Error
	if !errors.As(err, &le) {
		return &DirectoryError{}
	}
	switch le.ResultCode {
	case ldap.LDAPResultInvalidCredentials, ldap.ErrorEmptyPassword:
		return ErrInvalidCredentials
	case ldap.LDAPResultNoSuchObject:
		return ErrBaseNotFound
	case ldap.LDAPResultTimeLimitExceeded, ldap.LDAPResultTimeout:
		return ErrTimeout
	case ldap.ErrorFilterCompile, ldap.ErrorFilterDecompile:
		return ErrInvalidFilter
	case ldap.ErrorNetwork:
		return ErrUnreachable
	default:
		return &DirectoryError{Code: int(le.ResultCode)}
	}
}

// isTLSError reports certificate verification failures, TLS alerts (sent or
// received) and a non-TLS peer.
func isTLSError(err error) bool {
	var (
		unknownAuthority x509.UnknownAuthorityError
		hostname         x509.HostnameError
		invalid          x509.CertificateInvalidError
		verification     *tls.CertificateVerificationError
		recordHeader     tls.RecordHeaderError
		alert            tls.AlertError
		op               *net.OpError
	)
	switch {
	case errors.As(err, &unknownAuthority), errors.As(err, &hostname), errors.As(err, &invalid),
		errors.As(err, &verification), errors.As(err, &recordHeader), errors.As(err, &alert):
		return true
	case errors.As(err, &op):
		// crypto/tls reports alerts as *net.OpError{Op: "remote error"|"local error"}.
		return op.Op == "remote error" || op.Op == "local error"
	default:
		return false
	}
}

// reasons names each closed error for API responses and audit details.
var reasons = map[error]string{
	ErrTargetRefused:      "target_refused",
	ErrUnreachable:        "unreachable",
	ErrTimeout:            "timeout",
	ErrTLS:                "tls_failed",
	ErrInvalidCredentials: "invalid_credentials",
	ErrBaseNotFound:       "base_not_found",
	ErrInvalidFilter:      "invalid_filter",
	ErrInvalidBase:        "invalid_base",
	ErrInvalidURL:         "invalid_url",
	ErrInvalidCA:          "invalid_ca",
}

// Reason returns the stable reason code for err ("" for nil). Anything outside
// the named cases is "directory_error".
func Reason(err error) string {
	if err == nil {
		return ""
	}
	if r, ok := reasons[mapError(err)]; ok {
		return r
	}
	return "directory_error"
}
