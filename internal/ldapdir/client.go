package ldapdir

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const (
	// DefaultDialTimeout bounds the TCP connect and the ldaps handshake when
	// ConnParams.DialTimeout is zero.
	DefaultDialTimeout = 5 * time.Second
	// MaxBERPacketBytes caps a single LDAP message read from the server
	// (research D7), so a hostile server cannot make the client buffer an
	// arbitrarily large packet.
	MaxBERPacketBytes = 8 << 20
)

// TLS modes of a connection (research D3).
const (
	TLSModeLDAPS    = "ldaps"
	TLSModeStartTLS = "starttls"
	TLSModePlain    = "plain"
)

func init() {
	ber.MaxPacketLengthBytes = MaxBERPacketBytes
}

// errInvalidQuery refuses a Query the client will not send; it is a
// programming error in the caller, not something the directory said.
var errInvalidQuery = fmt.Errorf("%w: invalid query", ErrDirectory)

// Directory is the network side of the LDAP boundary. Client is the real
// implementation; ldapfake provides an in-memory one for tests.
type Directory interface {
	Open(ctx context.Context, c ConnParams) (Session, error)
}

// Session is one connection to a directory. It is not safe for concurrent use.
// Every method honours the ctx deadline: when it expires the connection is
// closed and the method returns ErrTimeout, so a session is single-use after
// a timeout.
type Session interface {
	// Bind performs a simple bind. The password is zeroed before Bind
	// returns; callers must not reuse the slice.
	Bind(ctx context.Context, dn string, password []byte) error
	BaseExists(ctx context.Context, baseDN string) error
	Search(ctx context.Context, q Query) (Page, error)
	TLSState() (tls.ConnectionState, bool)
	Close() error
}

// ConnParams describes how to reach a directory. TLSMode is one of
// TLSModeLDAPS (ldaps:// URL), TLSModeStartTLS or TLSModePlain (ldap:// URL).
type ConnParams struct {
	URL         string
	TLSMode     string
	CAPEM       string
	AllowTLS12  bool
	DialTimeout time.Duration
}

// Scope is the search scope; the zero value is the whole subtree.
type Scope int

// Search scopes.
const (
	ScopeSub Scope = iota // wholeSubtree
	ScopeOne              // singleLevel
)

// Query is one search. Filter must already be validated and combined with
// the connection's base filter; Attributes must be non-empty.
type Query struct {
	BaseDN     string
	Scope      Scope
	Filter     string
	Attributes []string
	SizeLimit  int
	TimeLimit  time.Duration
}

// Page is a search result of at most Query.SizeLimit entries. Truncated is set
// when more entries matched or the server hit its size or time limit.
// Referrals are counted, never followed.
type Page struct {
	Entries   []RawEntry
	Truncated bool
	Referrals int
}

// RawEntry is an undecoded entry; attribute names are lower-cased.
type RawEntry struct {
	DN    string
	Attrs map[string][][]byte
}

// Client is the go-ldap backed Directory. Every dial goes through the target
// policy's dialer.
type Client struct {
	policy *TargetPolicy
	// dialer builds the net.Dialer for one Open; tests replace it because
	// loopback is always denied by the policy.
	dialer func(time.Duration) *net.Dialer
}

// NewClient returns a Client that dials through p.
func NewClient(p *TargetPolicy) *Client {
	return &Client{policy: p, dialer: p.Dialer}
}

// Open validates the parameters, dials through the policy dialer and
// establishes TLS (ldaps or StartTLS). A failed StartTLS closes the
// connection; nothing is ever sent in plaintext after it.
func (c *Client) Open(ctx context.Context, p ConnParams) (Session, error) {
	ep, err := c.policy.CheckURL(p.URL)
	if err != nil {
		return nil, err
	}
	if !modeMatches(ep.Scheme, p.TLSMode) {
		return nil, fmt.Errorf("%w: tls mode does not match the URL scheme", ErrInvalidURL)
	}
	var tlsCfg *tls.Config
	if p.TLSMode != TLSModePlain {
		if tlsCfg, err = NewTLSConfig(ep, p.CAPEM, p.AllowTLS12); err != nil {
			return nil, err
		}
	}

	timeout := p.DialTimeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	d := c.dialer(timeout)
	if dl, ok := ctx.Deadline(); ok && (d.Deadline.IsZero() || dl.Before(d.Deadline)) {
		d.Deadline = dl
	}
	opts := []ldap.DialOpt{ldap.DialWithDialer(d)}
	if p.TLSMode == TLSModeLDAPS {
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}
	conn, err := ldap.DialURL(ep.Scheme+"://"+ep.Addr(), opts...)
	if err != nil {
		return nil, mapError(err)
	}

	if p.TLSMode == TLSModeStartTLS {
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		err = conn.StartTLS(tlsCfg)
		stop()
		if err != nil {
			_ = conn.Close()
			if ctx.Err() != nil {
				return nil, ErrTimeout
			}
			// go-ldap flattens the handshake cause into text, so classify
			// by step: any StartTLS failure is a TLS failure.
			return nil, ErrTLS
		}
	}
	return &session{conn: conn}, nil
}

func modeMatches(scheme, mode string) bool {
	switch mode {
	case TLSModeLDAPS:
		return scheme == "ldaps"
	case TLSModeStartTLS, TLSModePlain:
		return scheme == "ldap"
	default:
		return false
	}
}

type session struct {
	conn *ldap.Conn
}

// do runs one go-ldap call under ctx: go-ldap has no context support, so the
// connection is closed when ctx is done, which unblocks the call. A panic
// while decoding a hostile response is contained and closes the connection.
func (s *session) do(ctx context.Context, fn func() error) (err error) {
	stop := context.AfterFunc(ctx, func() { _ = s.conn.Close() })
	defer stop()
	defer func() {
		if r := recover(); r != nil {
			_ = s.conn.Close()
			err = &DirectoryError{}
		}
	}()
	if err = fn(); err != nil && ctx.Err() != nil {
		return ErrTimeout
	}
	return err
}

func (s *session) Bind(ctx context.Context, dn string, password []byte) error {
	defer clear(password)
	if len(password) == 0 {
		return ErrInvalidCredentials
	}
	req := &ldap.SimpleBindRequest{Username: dn, Password: string(password)}
	return mapError(s.do(ctx, func() error {
		_, err := s.conn.SimpleBind(req)
		return err
	}))
}

// BaseExists runs a base-scope search for baseDN without alias dereferencing.
func (s *session) BaseExists(ctx context.Context, baseDN string) error {
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, 0, false, "(objectClass=*)", []string{"1.1"}, nil)
	req.EnforceSizeLimit = true
	var res *ldap.SearchResult
	err := s.do(ctx, func() (err error) {
		res, err = s.conn.Search(req)
		return err
	})
	switch {
	case errors.Is(err, ldap.ErrSizeLimitExceeded):
		return nil // a base-scope search that returns entries found the base
	case err != nil:
		return mapError(err)
	case len(res.Entries) == 0:
		return ErrBaseNotFound
	default:
		return nil
	}
}

// Search asks for SizeLimit+1 entries so truncation is detectable, enforces
// that bound client-side even if the server ignores it, and returns at most
// SizeLimit entries.
//
//nolint:gocritic // hugeParam: Query is passed by value per contracts §C.
func (s *session) Search(ctx context.Context, q Query) (Page, error) {
	req, err := searchRequest(q)
	if err != nil {
		return Page{}, err
	}
	var res *ldap.SearchResult
	err = s.do(ctx, func() (err error) {
		res, err = s.conn.Search(req)
		return err
	})
	var page Page
	if err != nil {
		if !errors.Is(err, ldap.ErrSizeLimitExceeded) &&
			!ldap.IsErrorAnyOf(err, ldap.LDAPResultSizeLimitExceeded, ldap.LDAPResultTimeLimitExceeded) {
			return Page{}, mapError(err)
		}
		page.Truncated = true
	}
	entries := res.Entries
	if len(entries) > q.SizeLimit {
		entries = entries[:q.SizeLimit]
		page.Truncated = true
	}
	page.Referrals = len(res.Referrals)
	page.Entries = make([]RawEntry, len(entries))
	for i, e := range entries {
		attrs := make(map[string][][]byte, len(e.Attributes))
		for _, a := range e.Attributes {
			k := strings.ToLower(a.Name)
			attrs[k] = append(attrs[k], a.ByteValues...)
		}
		page.Entries[i] = RawEntry{DN: e.DN, Attrs: attrs}
	}
	return page, nil
}

//nolint:gocritic // hugeParam: see Search.
func searchRequest(q Query) (*ldap.SearchRequest, error) {
	var scope int
	switch q.Scope {
	case ScopeSub:
		scope = ldap.ScopeWholeSubtree
	case ScopeOne:
		scope = ldap.ScopeSingleLevel
	default:
		return nil, errInvalidQuery
	}
	// An empty attribute list means "all user attributes" on the wire.
	if len(q.Attributes) == 0 || q.SizeLimit < 1 || q.TimeLimit < 0 {
		return nil, errInvalidQuery
	}
	// Whole seconds, rounded up so a sub-second limit does not become 0
	// ("no limit").
	timeLimit := int((q.TimeLimit + time.Second - 1) / time.Second)
	req := ldap.NewSearchRequest(q.BaseDN, scope, ldap.NeverDerefAliases,
		q.SizeLimit+1, timeLimit, false, q.Filter, q.Attributes, nil)
	req.EnforceSizeLimit = true
	return req, nil
}

func (s *session) TLSState() (tls.ConnectionState, bool) {
	return s.conn.TLSConnectionState()
}

// Close closes the connection. It is idempotent; a failure to close has no
// consequence for the caller and is not reported.
func (s *session) Close() error {
	_ = s.conn.Close()
	return nil
}
