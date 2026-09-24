package directory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/ldapdir"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// Preview statuses (contracts §A SearchResult.items[].status).
const (
	StatusNew          = "new"
	StatusExistingUser = "existing_user"
	StatusImported     = "imported"
	StatusInvalid      = "invalid"
)

// searchGrace is added to the connection time limit for the client-side
// deadline, so the server's own limit (a truncated result) wins (D7).
const searchGrace = 2 * time.Second

// maxAuditFilter caps the canonical user filter kept in directory_searched
// details (D14).
const maxAuditFilter = 1024

var errPreview = errors.New("directory: reading the preview status failed")

// SearchRequest is a directory search (contracts §A). Empty fields mean
// (objectClass=*), the connection base and subtree scope.
type SearchRequest struct {
	Filter string `json:"filter"`
	Base   string `json:"base"`
	Scope  string `json:"scope"`
}

// SearchResult is the preview of a search. Items is never nil.
type SearchResult struct {
	Items           []SearchItem `json:"items"`
	Truncated       bool         `json:"truncated"`
	OutOfScope      int          `json:"out_of_scope"`
	EffectiveFilter string       `json:"effective_filter"`
}

// SearchItem is one previewed directory person. UserID is set for
// existing_user and imported, Reason for invalid.
type SearchItem struct {
	UID, DN, Email, DisplayName, FirstName, LastName string
	Status, UserID, Reason                           string
}

type searchItemWire struct {
	UID         string  `json:"uid"`
	DN          string  `json:"dn"`
	Email       *string `json:"email"`
	DisplayName string  `json:"display_name"`
	FirstName   string  `json:"first_name"`
	LastName    string  `json:"last_name"`
	Status      string  `json:"status"`
	UserID      *string `json:"user_id"`
	Reason      *string `json:"reason"`
}

// MarshalJSON writes an empty email, user_id or reason as null.
func (it SearchItem) MarshalJSON() ([]byte, error) { //nolint:gocritic // value receiver so []SearchItem marshals too
	null := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	return json.Marshal(searchItemWire{UID: it.UID, DN: it.DN, Email: null(it.Email), DisplayName: it.DisplayName,
		FirstName: it.FirstName, LastName: it.LastName, Status: it.Status, UserID: null(it.UserID), Reason: null(it.Reason)})
}

// UnmarshalJSON reads the wire form (null → "").
func (it *SearchItem) UnmarshalJSON(b []byte) error {
	var w searchItemWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	*it = SearchItem{UID: w.UID, DN: w.DN, Email: deref(w.Email), DisplayName: w.DisplayName, FirstName: w.FirstName,
		LastName: w.LastName, Status: w.Status, UserID: deref(w.UserID), Reason: deref(w.Reason)}
	return nil
}

// searchPlan is a validated search, ready to send.
type searchPlan struct {
	query    ldapdir.Query
	userCan  string // canonical user filter (audit)
	narrowed bool
	scope    string
}

// Search previews the people a filter selects under the connection base. The
// effective filter is always (&<base filter><user filter>) of canonical
// halves; invalid filters, bases and scopes are refused before any directory
// call; returned entries outside the base are dropped and counted. Searching
// is read-only and shares the per-tenant rate limit with connection tests.
func (s *Service) Search(ctx context.Context, actor tenantctx.Actor, tenantID, connID string, q SearchRequest) (SearchResult, error) { //nolint:gocritic // actor by value is the HTTP-facing signature
	c, err := s.lookup(ctx, &actor, tenantID, connID)
	if err != nil {
		return SearchResult{}, err
	}
	plan, err := planSearch(&c, &q)
	if err != nil {
		if errors.Is(err, ldapdir.ErrInvalidFilter) || errors.Is(err, ldapdir.ErrInvalidBase) {
			s.emitSearched(&actor, tenantID, connID, "refused", ldapdir.Reason(err), nil)
		}
		return SearchResult{}, err
	}
	if err := s.allow(ctx, tenantID); err != nil {
		if errors.Is(err, ErrRateLimited) {
			s.emitSearched(&actor, tenantID, connID, "refused", ErrRateLimited.Error(), nil)
		}
		return SearchResult{}, err
	}
	pw, err := s.testPassword(&Input{}, &c, tenantID, connID)
	if err != nil {
		return SearchResult{}, err
	}
	defer clear(pw)

	page, err := s.runSearch(ctx, &c, pw, &plan.query)
	if err != nil {
		s.emitSearched(&actor, tenantID, connID, "failed", ldapdir.Reason(err), plan.details(0, false))
		return SearchResult{}, err
	}
	res := SearchResult{Items: []SearchItem{}, Truncated: page.Truncated, EffectiveFilter: plan.query.Filter}
	if len(page.Entries) > plan.query.SizeLimit {
		page.Entries, res.Truncated = page.Entries[:plan.query.SizeLimit], true
	}
	m := mappingOf(&c)
	for i := range page.Entries {
		e := &page.Entries[i]
		if !ldapdir.WithinBase(plan.query.BaseDN, e.DN) {
			res.OutOfScope++
			continue
		}
		p, derr := ldapdir.Decode(m, *e)
		it := SearchItem{UID: p.UID, DN: p.DN, Email: p.Email, DisplayName: p.DisplayName, FirstName: p.FirstName, LastName: p.LastName}
		if derr != nil {
			it.Status, it.Reason = StatusInvalid, ldapdir.Reason(derr)
		}
		res.Items = append(res.Items, it)
	}
	if err := s.previewStatus(ctx, tenantID, connID, res.Items); err != nil {
		return SearchResult{}, err
	}
	s.emitSearched(&actor, tenantID, connID, "ok", "", plan.details(len(res.Items), res.Truncated))
	return res, nil
}

// planSearch compiles and combines the filters, scopes the base and builds
// the query. It never contacts the directory.
func planSearch(c *store.DirectoryConnection, q *SearchRequest) (searchPlan, error) {
	var p searchPlan
	switch q.Scope {
	case "", "sub":
		p.query.Scope, p.scope = ldapdir.ScopeSub, "sub"
	case "one":
		p.query.Scope, p.scope = ldapdir.ScopeOne, "one"
	default:
		return searchPlan{}, ErrValidation
	}
	user, err := ldapdir.CompileUserFilter(q.Filter)
	if err != nil {
		return searchPlan{}, err
	}
	base, err := ldapdir.CompileUserFilter(c.BaseFilter)
	if err != nil {
		return searchPlan{}, err
	}
	effective, err := ldapdir.Combine(base, user)
	if err != nil {
		return searchPlan{}, err
	}
	baseDN, err := ldapdir.ScopeBase(c.BaseDN, q.Base)
	if err != nil {
		return searchPlan{}, err
	}
	p.userCan, p.narrowed = user.String(), q.Base != ""
	p.query.BaseDN = baseDN
	p.query.Filter = effective.String()
	p.query.Attributes = mappedAttributes(c)
	p.query.SizeLimit = c.SizeLimit
	p.query.TimeLimit = time.Duration(c.TimeLimitSeconds) * time.Second
	return p, nil
}

// details is the directory_searched payload: never entries (D14).
func (p *searchPlan) details(count int, truncated bool) map[string]any {
	f := p.userCan
	if len(f) > maxAuditFilter {
		f = f[:maxAuditFilter]
	}
	d := map[string]any{"filter": f, "scope": p.scope, "count": count, "truncated": truncated}
	if p.narrowed {
		d["base"] = p.query.BaseDN
	}
	return d
}

// runSearch opens, binds and searches under one deadline (dial + time limit
// + grace). Bind zeroes pw. The session is always closed.
func (s *Service) runSearch(ctx context.Context, c *store.DirectoryConnection, pw []byte, q *ldapdir.Query) (ldapdir.Page, error) {
	dial := s.d.Config.DialTimeout
	if dial <= 0 {
		dial = ldapdir.DefaultDialTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, dial+q.TimeLimit+searchGrace)
	defer cancel()

	sess, err := s.d.Directory.Open(ctx, ldapdir.ConnParams{
		URL: c.URL, TLSMode: c.TLSMode, CAPEM: c.CAPEM, AllowTLS12: c.AllowTLS12, DialTimeout: s.d.Config.DialTimeout,
	})
	if err != nil {
		return ldapdir.Page{}, closedDirErr(err)
	}
	defer func() { _ = sess.Close() }()
	if c.TLSMode != ldapdir.TLSModePlain {
		if st, ok := sess.TLSState(); !ok || !st.HandshakeComplete {
			return ldapdir.Page{}, ldapdir.ErrTLS
		}
	}
	if err := sess.Bind(ctx, c.BindDN, pw); err != nil {
		return ldapdir.Page{}, closedDirErr(err)
	}
	page, err := sess.Search(ctx, *q)
	if err != nil {
		return ldapdir.Page{}, closedDirErr(err)
	}
	return page, nil
}

// closedDirErr keeps a deadline that surfaced as a context error inside the
// closed vocabulary.
func closedDirErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ldapdir.ErrTimeout
	}
	return err
}

// previewStatus sets the status of every valid item. A link of this
// connection decides first (imported while its user is still imported,
// existing_user once activated); otherwise a tenant user with the same
// e-mail makes it existing_user; else it is new.
func (s *Service) previewStatus(ctx context.Context, tenantID, connID string, items []SearchItem) error {
	var uids, emails []string
	for i := range items {
		if items[i].Status == "" {
			uids = append(uids, items[i].UID)
			emails = append(emails, items[i].Email)
		}
	}
	if len(uids) == 0 {
		return nil
	}
	links, err := s.d.Store.LinksByUIDs(ctx, tenantID, connID, uids)
	if err != nil {
		return errPreview
	}
	found, err := s.d.Store.UsersByEmails(ctx, tenantID, emails)
	if err != nil {
		return errPreview
	}
	byEmail := make(map[string]store.User, len(found))
	for email := range found {
		byEmail[strings.ToLower(email)] = found[email]
	}
	for i := range items {
		it := &items[i]
		if it.Status != "" {
			continue
		}
		if l, ok := links[it.UID]; ok {
			u, err := s.d.Store.User(ctx, tenantID, l.UserID)
			switch {
			case err == nil:
				it.Status, it.UserID = StatusExistingUser, u.ID
				if u.Status == "imported" {
					it.Status = StatusImported
				}
				continue
			case !errors.Is(err, store.ErrNotFound):
				return errPreview
			}
		}
		if u, ok := byEmail[it.Email]; ok {
			it.Status, it.UserID = StatusExistingUser, u.ID
			continue
		}
		it.Status = StatusNew
	}
	return nil
}

// mappingOf is the connection's attribute mapping for ldapdir.Decode.
func mappingOf(c *store.DirectoryConnection) ldapdir.Mapping {
	return ldapdir.Mapping{UID: c.AttrUID, Email: c.AttrEmail, DisplayName: c.AttrDisplayName, FirstName: c.AttrFirstName, LastName: c.AttrLastName}
}

// mappedAttributes lists the non-empty mapped attributes: never "*".
func mappedAttributes(c *store.DirectoryConnection) []string {
	var out []string
	for _, a := range []string{c.AttrUID, c.AttrEmail, c.AttrDisplayName, c.AttrFirstName, c.AttrLastName} {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

// emitSearched writes directory_searched (outcome ok/failed/refused).
func (s *Service) emitSearched(actor *tenantctx.Actor, tenantID, connID, outcome, reason string, details map[string]any) {
	e := audit.Event{Type: audit.DirectorySearched, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID,
		SubjectKind: subjectKind, SubjectID: connID, Outcome: outcome, Reason: reason, Details: details}
	s.emit(&e)
}
