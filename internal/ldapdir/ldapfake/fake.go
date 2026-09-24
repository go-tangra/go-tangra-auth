package ldapfake

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/go-freya/freya/services/auth/internal/ldapdir"
)

// LDAP result codes the fake reports as *ldapdir.DirectoryError, the same
// shape the real client produces for them.
const (
	codeReferral     = 10 // base DN lies at or below a referral object
	codeUnwilling    = 53 // unsupported extensible match rule
	matchBitAnd      = "1.2.840.113556.1.4.803"
	matchBitOr       = "1.2.840.113556.1.4.804"
	attrObjectClass  = "objectclass"
	attrAliasedObjDN = "aliasedobjectname"
)

// errInvalidQuery mirrors the real client's refusal of a Query it would not
// send (unknown scope, no attributes, SizeLimit < 1, negative TimeLimit).
var errInvalidQuery = fmt.Errorf("%w: invalid query", ldapdir.ErrDirectory)

// Op names a Directory/Session operation for error injection.
type Op int

// Operations that accept injected errors.
const (
	OpOpen Op = iota
	OpBind
	OpBaseExists
	OpSearch
)

// Entry is a directory object. Attribute names are case-insensitive; values
// are raw bytes so binary attributes (objectGUID) can be modelled.
type Entry struct {
	DN    string
	Attrs map[string][][]byte
}

// Vals converts strings to attribute values.
func Vals(vs ...string) [][]byte {
	out := make([][]byte, len(vs))
	for i, v := range vs {
		out[i] = []byte(v)
	}
	return out
}

// SearchCall is one Search as the session received it, plus what the real
// client would put on the wire for it.
type SearchCall struct {
	Query ldapdir.Query
	// Deref is the alias dereferencing the real client requests; it is
	// always ldap.NeverDerefAliases.
	Deref int
	// WireSizeLimit is Query.SizeLimit+1 and WireTimeLimit is TimeLimit
	// rounded up to whole seconds, as the real client sends them.
	WireSizeLimit int
	WireTimeLimit int
}

// BindCall is one Bind. Password is a copy taken before the caller's slice
// is zeroed; fixtures must use obviously fake credentials.
type BindCall struct {
	DN       string
	Password string
}

type node struct {
	entry    Entry
	dn       *ldap.DN
	alias    *ldap.DN // aliasedObjectName for alias entries
	referral string   // referral URL for referral objects
}

// Directory is an in-memory ldapdir.Directory. The zero value is not usable;
// call New. It is safe for concurrent use.
type Directory struct {
	mu        sync.Mutex
	nodes     []*node
	creds     map[string]string
	errs      map[Op][]error
	derefs    bool
	delay     time.Duration
	adminSize int // server-side size limit; 0 = none
	timeAfter int // entries returned before the server time limit; -1 = never
	tlsVer    uint16

	opens      []ldapdir.ConnParams
	binds      []BindCall
	baseChecks []string
	searches   []SearchCall
	live       int
}

var _ ldapdir.Directory = (*Directory)(nil)

// New returns an empty directory that honours NeverDerefAliases, has no
// server-side limits and negotiates TLS 1.3.
func New() *Directory {
	return &Directory{
		creds:     map[string]string{},
		errs:      map[Op][]error{},
		timeAfter: -1,
		tlsVer:    tls.VersionTLS13,
	}
}

func mustDN(s string) *ldap.DN {
	dn, err := ldap.ParseDN(s)
	if err != nil {
		panic(fmt.Sprintf("ldapfake: invalid DN %q: %v", s, err))
	}
	return dn
}

func (d *Directory) add(n *node) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nodes = append(d.nodes, n)
}

// Add stores an entry. Parents are not created implicitly: a base DN exists
// only if an entry was added for it. It panics on an unparsable DN.
func (d *Directory) Add(e Entry) {
	attrs := make(map[string][][]byte, len(e.Attrs))
	for k, vs := range e.Attrs {
		k = strings.ToLower(k)
		for _, v := range vs {
			attrs[k] = append(attrs[k], bytes.Clone(v))
		}
	}
	d.add(&node{entry: Entry{DN: e.DN, Attrs: attrs}, dn: mustDN(e.DN)})
}

// AddAlias stores an alias object at dn pointing at target (which may lie
// outside any base).
func (d *Directory) AddAlias(dn, target string) {
	d.add(&node{
		entry: Entry{DN: dn, Attrs: map[string][][]byte{
			attrObjectClass:  Vals("top", "alias", "extensibleObject"),
			attrAliasedObjDN: Vals(target),
		}},
		dn:    mustDN(dn),
		alias: mustDN(target),
	})
}

// AddReferral stores a referral object at dn. Searches whose scope covers it
// count it in Page.Referrals; a search based at or below it fails with
// result code 10 (referral), which the real client reports as a
// DirectoryError.
func (d *Directory) AddReferral(dn, url string) {
	d.add(&node{
		entry: Entry{DN: dn, Attrs: map[string][][]byte{
			attrObjectClass: Vals("top", "referral", "extensibleObject"),
			"ref":           Vals(url),
		}},
		dn:       mustDN(dn),
		referral: url,
	})
}

// SetCredentials accepts password for a simple bind as dn.
func (d *Directory) SetCredentials(dn, password string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.creds[strings.ToLower(mustDN(dn).String())] = password
}

// SetDerefAliases makes the fake dereference aliases despite the
// NeverDerefAliases the client requests, modelling a misbehaving server: an
// alias in scope is replaced by its target, wherever that lives.
func (d *Directory) SetDerefAliases(on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.derefs = on
}

// SetServerSizeLimit models an administrative size limit: a search matching
// more than n entries returns n and is truncated (result code 4). 0 = none.
func (d *Directory) SetServerSizeLimit(n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.adminSize = n
}

// SetTimeLimitAfter models the server's time limit expiring after n matching
// entries: the search returns those entries and is truncated (result code 3).
// A negative n disables it.
func (d *Directory) SetTimeLimitAfter(n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.timeAfter = n
}

// SetDelay makes Bind, BaseExists and Search take delay. If the ctx deadline
// expires first the call returns ErrTimeout and the session becomes unusable,
// as with the real client.
func (d *Directory) SetDelay(delay time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.delay = delay
}

// SetTLSVersion sets the version TLSState reports for ldaps/starttls sessions.
func (d *Directory) SetTLSVersion(v uint16) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tlsVer = v
}

// InjectError queues errs for the next calls of op, one per call, in order.
// A nil entry lets that call run normally. Injected errors should be ldapdir
// sentinels or *ldapdir.DirectoryError, as the real client returns.
func (d *Directory) InjectError(op Op, errs ...error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.errs[op] = append(d.errs[op], errs...)
}

func (d *Directory) injected(op Op) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	q := d.errs[op]
	if len(q) == 0 {
		return nil
	}
	d.errs[op] = q[1:]
	return q[0]
}

// Opens returns every ConnParams passed to Open.
func (d *Directory) Opens() []ldapdir.ConnParams {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]ldapdir.ConnParams(nil), d.opens...)
}

// Binds returns every Bind, including failed ones.
func (d *Directory) Binds() []BindCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]BindCall(nil), d.binds...)
}

// BaseChecks returns the DN of every BaseExists call.
func (d *Directory) BaseChecks() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.baseChecks...)
}

// Searches returns every Search the sessions received, including ones that
// failed validation or had an error injected.
func (d *Directory) Searches() []SearchCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]SearchCall, len(d.searches))
	for i, s := range d.searches {
		s.Query.Attributes = append([]string(nil), s.Query.Attributes...)
		out[i] = s
	}
	return out
}

// OpenSessions is the number of sessions opened and not yet closed, so tests
// can assert that callers always Close.
func (d *Directory) OpenSessions() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.live
}

// Open records p and returns a session, or the injected error. The fake does
// not dial or apply the target policy; inject ErrTargetRefused, ErrUnreachable,
// ErrTLS, ... to exercise those paths.
func (d *Directory) Open(ctx context.Context, p ldapdir.ConnParams) (ldapdir.Session, error) {
	d.mu.Lock()
	d.opens = append(d.opens, p)
	d.mu.Unlock()
	if err := d.injected(OpOpen); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ldapdir.ErrTimeout
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.live++
	return &session{d: d, tls: p.TLSMode == ldapdir.TLSModeLDAPS || p.TLSMode == ldapdir.TLSModeStartTLS}, nil
}

type session struct {
	d      *Directory
	tls    bool
	closed bool
	dead   bool // timed out; single-use like the real client
}

// begin applies the injected error, the delay and the ctx deadline shared by
// every session call.
func (s *session) begin(ctx context.Context, op Op) error {
	if s.closed || s.dead {
		return ldapdir.ErrUnreachable
	}
	if err := s.d.injected(op); err != nil {
		if errors.Is(err, ldapdir.ErrTimeout) {
			s.dead = true
		}
		return err
	}
	s.d.mu.Lock()
	delay := s.d.delay
	s.d.mu.Unlock()
	if delay > 0 {
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
		}
	}
	if ctx.Err() != nil {
		s.dead = true
		return ldapdir.ErrTimeout
	}
	return nil
}

func (s *session) Bind(ctx context.Context, dn string, password []byte) error {
	defer clear(password)
	s.d.mu.Lock()
	s.d.binds = append(s.d.binds, BindCall{DN: dn, Password: string(password)})
	s.d.mu.Unlock()
	if len(password) == 0 {
		return ldapdir.ErrInvalidCredentials
	}
	if err := s.begin(ctx, OpBind); err != nil {
		return err
	}
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return ldapdir.ErrInvalidCredentials
	}
	s.d.mu.Lock()
	want, ok := s.d.creds[strings.ToLower(parsed.String())]
	s.d.mu.Unlock()
	if !ok || want != string(password) {
		return ldapdir.ErrInvalidCredentials
	}
	return nil
}

// BaseExists succeeds when an entry (including an alias, which is not
// dereferenced) exists at baseDN.
func (s *session) BaseExists(ctx context.Context, baseDN string) error {
	s.d.mu.Lock()
	s.d.baseChecks = append(s.d.baseChecks, baseDN)
	s.d.mu.Unlock()
	if err := s.begin(ctx, OpBaseExists); err != nil {
		return err
	}
	base, err := ldap.ParseDN(baseDN)
	if err != nil {
		return ldapdir.ErrBaseNotFound
	}
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	if n, ref := s.d.lookup(base); ref {
		return &ldapdir.DirectoryError{Code: codeReferral}
	} else if n == nil {
		return ldapdir.ErrBaseNotFound
	}
	return nil
}

// lookup finds the node at dn; ref reports that dn lies at or below a
// referral object. Callers hold d.mu.
func (d *Directory) lookup(dn *ldap.DN) (found *node, ref bool) {
	for _, n := range d.nodes {
		if n.referral != "" && (n.dn.EqualFold(dn) || n.dn.AncestorOfFold(dn)) {
			return nil, true
		}
		if n.dn.EqualFold(dn) {
			found = n
		}
	}
	return found, false
}

//nolint:gocritic // hugeParam: Query is passed by value per contracts §C.
func (s *session) Search(ctx context.Context, q ldapdir.Query) (ldapdir.Page, error) {
	s.d.mu.Lock()
	q.Attributes = append([]string(nil), q.Attributes...)
	s.d.searches = append(s.d.searches, SearchCall{
		Query:         q,
		Deref:         ldap.NeverDerefAliases,
		WireSizeLimit: q.SizeLimit + 1,
		WireTimeLimit: int((q.TimeLimit + time.Second - 1) / time.Second),
	})
	s.d.mu.Unlock()

	if (q.Scope != ldapdir.ScopeSub && q.Scope != ldapdir.ScopeOne) ||
		len(q.Attributes) == 0 || q.SizeLimit < 1 || q.TimeLimit < 0 {
		return ldapdir.Page{}, errInvalidQuery
	}
	filter, err := ldap.CompileFilter(q.Filter)
	if err != nil {
		return ldapdir.Page{}, ldapdir.ErrInvalidFilter
	}
	if err := s.begin(ctx, OpSearch); err != nil {
		return ldapdir.Page{}, err
	}
	base, err := ldap.ParseDN(q.BaseDN)
	if err != nil {
		return ldapdir.Page{}, ldapdir.ErrBaseNotFound
	}

	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	if n, ref := s.d.lookup(base); ref {
		return ldapdir.Page{}, &ldapdir.DirectoryError{Code: codeReferral}
	} else if n == nil {
		return ldapdir.Page{}, ldapdir.ErrBaseNotFound
	}

	var page ldapdir.Page
	var matched []*node
	for _, n := range s.d.nodes {
		if !inScope(base, n.dn, q.Scope) {
			continue
		}
		if n.referral != "" {
			page.Referrals++
			continue
		}
		if n.alias != nil && s.d.derefs {
			if n = s.d.target(n.alias); n == nil {
				continue
			}
		}
		ok, err := match(filter, n.entry.Attrs)
		if err != nil {
			return ldapdir.Page{}, err
		}
		if ok {
			matched = append(matched, n)
		}
	}

	limit := q.SizeLimit
	if s.d.adminSize > 0 && s.d.adminSize < limit {
		limit = s.d.adminSize
	}
	if s.d.timeAfter >= 0 && s.d.timeAfter < len(matched) && s.d.timeAfter < limit {
		limit = s.d.timeAfter
	}
	if len(matched) > limit {
		matched = matched[:limit]
		page.Truncated = true
	}
	page.Entries = make([]ldapdir.RawEntry, len(matched))
	for i, n := range matched {
		page.Entries[i] = project(n.entry, q.Attributes)
	}
	return page, nil
}

// target resolves an alias to a non-alias, non-referral entry (one hop, as
// alias chains are not followed). Callers hold d.mu.
func (d *Directory) target(dn *ldap.DN) *node {
	for _, n := range d.nodes {
		if n.dn.EqualFold(dn) && n.alias == nil && n.referral == "" {
			return n
		}
	}
	return nil
}

func inScope(base, dn *ldap.DN, scope ldapdir.Scope) bool {
	if scope == ldapdir.ScopeOne {
		return len(dn.RDNs) == len(base.RDNs)+1 && base.AncestorOfFold(dn)
	}
	return base.EqualFold(dn) || base.AncestorOfFold(dn)
}

// project returns a copy of e holding only the requested attributes ("*" =
// all, "1.1" = none), with lower-cased names.
func project(e Entry, want []string) ldapdir.RawEntry {
	all := false
	set := map[string]bool{}
	for _, a := range want {
		if a == "*" {
			all = true
		}
		set[strings.ToLower(a)] = true
	}
	attrs := map[string][][]byte{}
	for k, vs := range e.Attrs {
		if !all && !set[k] {
			continue
		}
		for _, v := range vs {
			attrs[k] = append(attrs[k], bytes.Clone(v))
		}
	}
	return ldapdir.RawEntry{DN: e.DN, Attrs: attrs}
}

// match evaluates a compiled filter against attrs with case-insensitive
// string matching. Undefined results count as false.
func match(f *ber.Packet, attrs map[string][][]byte) (bool, error) {
	switch f.Tag {
	case ldap.FilterAnd:
		for _, c := range f.Children {
			if ok, err := match(c, attrs); err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	case ldap.FilterOr:
		for _, c := range f.Children {
			if ok, err := match(c, attrs); err != nil || ok {
				return ok, err
			}
		}
		return false, nil
	case ldap.FilterNot:
		ok, err := match(f.Children[0], attrs)
		return !ok, err
	case ldap.FilterPresent:
		return len(attrs[strings.ToLower(f.Data.String())]) > 0, nil
	case ldap.FilterSubstrings:
		vals := attrs[attrName(f)]
		return slices.ContainsFunc(vals, func(v []byte) bool { return substr(v, f.Children[1].Children) }), nil
	case ldap.FilterExtensibleMatch:
		return extensible(f, attrs)
	default: // equality, approx, >=, <=
		vals := attrs[attrName(f)]
		want := f.Children[1].Data.Bytes()
		return slices.ContainsFunc(vals, func(v []byte) bool { return compare(v, want, f.Tag) }), nil
	}
}

func attrName(f *ber.Packet) string {
	return strings.ToLower(f.Children[0].Data.String())
}

func fold(b []byte) []byte {
	if utf8.Valid(b) {
		return bytes.ToLower(b)
	}
	return b
}

func compare(v, want []byte, tag ber.Tag) bool {
	c := bytes.Compare(fold(v), fold(want))
	switch tag {
	case ldap.FilterGreaterOrEqual:
		return c >= 0
	case ldap.FilterLessOrEqual:
		return c <= 0
	default:
		return c == 0
	}
}

func substr(v []byte, parts []*ber.Packet) bool {
	v = fold(v)
	for _, p := range parts {
		s := fold(p.Data.Bytes())
		switch p.Tag {
		case ldap.FilterSubstringsInitial:
			if !bytes.HasPrefix(v, s) {
				return false
			}
			v = v[len(s):]
		case ldap.FilterSubstringsFinal:
			if !bytes.HasSuffix(v, s) {
				return false
			}
			v = v[:len(v)-len(s)]
		default:
			i := bytes.Index(v, s)
			if i < 0 {
				return false
			}
			v = v[i+len(s):]
		}
	}
	return true
}

// extensible supports the Active Directory bitwise rules (LDAP_MATCHING_RULE_
// BIT_AND/OR) and rule-less equality; other rules are refused with result
// code 53, as a server lacking them would.
func extensible(f *ber.Packet, attrs map[string][][]byte) (bool, error) {
	var rule, attr string
	var value []byte
	for _, c := range f.Children {
		switch c.Tag {
		case ldap.MatchingRuleAssertionMatchingRule:
			rule = c.Data.String()
		case ldap.MatchingRuleAssertionType:
			attr = strings.ToLower(c.Data.String())
		case ldap.MatchingRuleAssertionMatchValue:
			value = c.Data.Bytes()
		}
	}
	vals := attrs[attr]
	switch rule {
	case "":
		return slices.ContainsFunc(vals, func(v []byte) bool { return compare(v, value, ldap.FilterEqualityMatch) }), nil
	case matchBitAnd, matchBitOr:
		want, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil {
			return false, nil
		}
		return slices.ContainsFunc(vals, func(v []byte) bool {
			got, err := strconv.ParseInt(string(v), 10, 64)
			if err != nil {
				return false
			}
			if rule == matchBitAnd {
				return got&want == want
			}
			return got&want != 0
		}), nil
	default:
		return false, &ldapdir.DirectoryError{Code: codeUnwilling}
	}
}

// TLSState reports a completed handshake for ldaps and starttls sessions.
func (s *session) TLSState() (tls.ConnectionState, bool) {
	if !s.tls {
		return tls.ConnectionState{}, false
	}
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	return tls.ConnectionState{Version: s.d.tlsVer, HandshakeComplete: true}, true
}

// Close is idempotent and always returns nil, like the real client.
func (s *session) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	s.d.live--
	return nil
}
