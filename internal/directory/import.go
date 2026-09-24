package directory

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/ldapdir"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// MaxImportUIDs bounds one import request (FR-006, research D8).
const MaxImportUIDs = 500

// Per-entry import reasons (contracts §A ImportResult). Skipped reasons
// that come from decoding are the ldapdir ones (no_email, invalid_email,
// value_too_long, ...).
const (
	ReasonEmailInUse     = "email_in_use"
	ReasonDuplicateEmail = "duplicate_email"
	ReasonAlreadyActive  = "already_active"
	ReasonNotFound       = "not_found_in_directory"
	ReasonDirectoryError = "directory_error"
	ReasonTimeout        = "timeout"
	ReasonInternal       = "internal"
)

// errImportTx is returned when the store hands Atomic something that is not
// an ImportTx (a wiring bug, reported per entry as internal).
var errImportTx = errors.New("directory: store transaction is not an ImportTx")

// ImportTx is the per-entry import transaction (directorydb in production,
// memstore in tests). Every call is tenant scoped.
type ImportTx interface {
	UserByEmail(ctx context.Context, tenantID, email string) (store.User, error)
	User(ctx context.Context, tenantID, id string) (store.User, error)
	LinksByUIDs(ctx context.Context, tenantID, connID string, uids []string) (map[string]store.DirectoryLink, error)
	// InsertUser creates the user as given (status imported); a taken
	// e-mail is store.ErrConflict.
	InsertUser(ctx context.Context, u store.User) error
	// UpdateImportedUser only touches a user that is still imported.
	UpdateImportedUser(ctx context.Context, tenantID, userID string, p store.ImportedProfile) error
	UpsertLink(ctx context.Context, l store.DirectoryLink) error
}

// ImportResult is the per-entry outcome of an import; every requested uid
// appears in exactly one list. Empty lists marshal as [].
type ImportResult struct {
	Created []ImportItem  `json:"created"`
	Updated []ImportItem  `json:"updated"`
	Skipped []ImportIssue `json:"skipped"`
	Failed  []ImportIssue `json:"failed"`
}

// ImportItem is a created or updated user.
type ImportItem struct {
	UID    string `json:"uid"`
	UserID string `json:"user_id"`
}

// ImportIssue is a skipped or failed entry with its closed reason.
type ImportIssue struct {
	UID    string `json:"uid"`
	Reason string `json:"reason"`
}

// MarshalJSON writes nil lists as [].
func (r ImportResult) MarshalJSON() ([]byte, error) { //nolint:gocritic // value receiver so a zero ImportResult marshals too
	type wire ImportResult
	w := wire(r)
	if w.Created == nil {
		w.Created = []ImportItem{}
	}
	if w.Updated == nil {
		w.Updated = []ImportItem{}
	}
	if w.Skipped == nil {
		w.Skipped = []ImportIssue{}
	}
	if w.Failed == nil {
		w.Failed = []ImportIssue{}
	}
	return json.Marshal(w)
}

// importRun is the state of one import request.
type importRun struct {
	s        *Service
	actor    *tenantctx.Actor
	tenantID string
	c        *store.DirectoryConnection
	base     string // canonical base filter
	mapping  ldapdir.Mapping
	attrs    []string
	now      time.Time
	emails   map[string]bool // e-mails created or refreshed by this request
	res      ImportResult
}

// Import re-fetches every selected directory uid with the exact-match filter
// (&<base filter>(<uid attr>=<escaped uid>)) under the connection base, so a
// caller can neither forge entries nor inject filter syntax, and stores each
// entry in its own transaction: new people become "imported" users (no
// password, no MFA, never an e-mail) with a link row; people already linked
// to this connection are refreshed while still imported and left alone once
// activated. When the directory cannot be reached or bound at all the bare
// ldapdir error is returned and nothing is imported.
func (s *Service) Import(ctx context.Context, actor tenantctx.Actor, tenantID, connID string, uids []string) (ImportResult, error) { //nolint:gocritic // actor by value is the HTTP-facing signature
	if err := validUIDs(uids); err != nil {
		return ImportResult{}, err
	}
	c, err := s.lookup(ctx, &actor, tenantID, connID)
	if err != nil {
		return ImportResult{}, err
	}
	if err := s.usable(&c); err != nil {
		s.refused(audit.DirectoryImported, &actor, tenantID, connID, err)
		return ImportResult{}, err
	}
	base, err := ldapdir.CompileUserFilter(c.BaseFilter)
	if err != nil {
		return ImportResult{}, err
	}
	// One import is one outbound session: it counts against the same
	// per-tenant limit as tests and searches, or it would be an unmetered
	// dial probe (T070).
	if err := s.allow(ctx, tenantID); err != nil {
		if errors.Is(err, ErrRateLimited) {
			s.emitImported(&actor, tenantID, connID, "refused", ErrRateLimited.Error(), nil)
		}
		return ImportResult{}, err
	}
	pw, err := s.testPassword(&Input{}, &c, tenantID, connID)
	if err != nil {
		return ImportResult{}, err
	}
	sess, err := s.openBound(ctx, &c, pw)
	clear(pw)
	if err != nil {
		s.emitImported(&actor, tenantID, connID, "failed", ldapdir.Reason(err), nil)
		return ImportResult{}, err
	}

	r := &importRun{s: s, actor: &actor, tenantID: tenantID, c: &c, base: base.String(), mapping: mappingOf(&c),
		attrs: mappedAttributes(&c), now: s.d.Now().UTC(), emails: map[string]bool{}}
	var reopen error // set once a lost session cannot be reopened
	for _, uid := range uids {
		if reopen != nil {
			r.fail(uid, reopen)
			continue
		}
		if sess == nil {
			if sess, reopen = s.reopen(ctx, &c, tenantID, connID); reopen != nil {
				r.fail(uid, reopen)
				continue
			}
		}
		if err := r.entry(ctx, sess, uid); err != nil {
			// A timed-out or dropped session is single-use: reopen it for
			// the next entry. A plain LDAP result code leaves it usable.
			var de *ldapdir.DirectoryError
			if !errors.As(err, &de) {
				_ = sess.Close()
				sess = nil
			}
		}
	}
	if sess != nil {
		_ = sess.Close()
	}
	s.emitImported(&actor, tenantID, connID, "ok", "", r.details(connID))
	return r.res, nil
}

// validUIDs refuses an empty, over-long, duplicated or blank uid list.
func validUIDs(uids []string) error {
	if len(uids) == 0 || len(uids) > MaxImportUIDs {
		return ErrValidation
	}
	seen := make(map[string]bool, len(uids))
	for _, u := range uids {
		if strings.TrimSpace(u) == "" || seen[u] {
			return ErrValidation
		}
		seen[u] = true
	}
	return nil
}

// entry imports one uid. It returns the directory error of the re-fetch (the
// entry is already reported as failed) so the caller can drop the session.
func (r *importRun) entry(ctx context.Context, sess ldapdir.Session, uid string) error {
	value, ok := r.assertionValue(uid)
	if !ok {
		// A uid Decode could never produce cannot be linked: no query.
		r.skip(uid, ReasonNotFound)
		return nil
	}
	q := ldapdir.Query{
		BaseDN: r.c.BaseDN, Scope: ldapdir.ScopeSub,
		Filter:     "(&" + r.base + "(" + r.mapping.UID + "=" + ldap.EscapeFilter(value) + "))",
		Attributes: r.attrs, SizeLimit: 2, TimeLimit: time.Duration(r.c.TimeLimitSeconds) * time.Second,
	}
	sctx, cancel := context.WithTimeout(ctx, q.TimeLimit+searchGrace)
	page, err := sess.Search(sctx, q)
	cancel()
	if err != nil {
		err = closedDirErr(err)
		r.fail(uid, err)
		return err
	}
	var found []ldapdir.RawEntry
	for i := range page.Entries {
		if ldapdir.WithinBase(r.c.BaseDN, page.Entries[i].DN) {
			found = append(found, page.Entries[i])
		}
	}
	switch {
	case len(found) == 0:
		r.skip(uid, ReasonNotFound)
		return nil
	case len(found) > 1:
		// The unique id is not unique in this directory: import no one.
		r.failReason(uid, ReasonDirectoryError)
		return nil
	}
	p, err := ldapdir.Decode(r.mapping, found[0])
	if err != nil {
		r.skip(uid, ldapdir.Reason(err))
		return nil
	}
	r.store(ctx, uid, &p)
	return nil
}

// assertionValue is the raw value the uid attribute must equal: the 16
// objectGUID bytes for AD, the uid itself otherwise. ok is false for uids
// ldapdir.Decode could never return.
func (r *importRun) assertionValue(uid string) (string, bool) {
	if strings.EqualFold(r.mapping.UID, "objectGUID") {
		b, ok := parseGUID(uid)
		return string(b), ok
	}
	if len(uid) > ldapdir.MaxUIDBytes || !utf8.ValidString(uid) || strings.ContainsFunc(uid, isControl) {
		return "", false
	}
	return uid, true
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) }

// parseGUID reverses ldapdir's canonical GUID rendering: the first three
// groups are little-endian, the last two in byte order.
func parseGUID(s string) ([]byte, bool) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return nil, false
	}
	g, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(g) != 16 {
		return nil, false
	}
	b := []byte{g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6]}
	return append(b, g[8:]...), true
}

// store writes one decoded entry in its own transaction. Skips write
// nothing; any store error rolls the entry back and reports it as internal.
func (r *importRun) store(ctx context.Context, uid string, p *ldapdir.Person) {
	if r.emails[p.Email] {
		r.skip(uid, ReasonDuplicateEmail)
		return
	}
	var (
		reason, userID string
		created        bool
	)
	err := r.s.d.Store.Atomic(ctx, store.Scope{TenantID: r.tenantID}, func(raw any) error {
		tx, ok := raw.(ImportTx)
		if !ok {
			return errImportTx
		}
		var err error
		reason, userID, created, err = r.write(ctx, tx, p)
		return err
	})
	switch {
	case err != nil:
		r.failReason(uid, ReasonInternal)
	case reason != "":
		r.skip(uid, reason)
	case created:
		r.emails[p.Email] = true
		r.res.Created = append(r.res.Created, ImportItem{UID: uid, UserID: userID})
	default:
		r.emails[p.Email] = true
		r.res.Updated = append(r.res.Updated, ImportItem{UID: uid, UserID: userID})
	}
}

// write applies research D8 inside the entry transaction. A non-empty
// reason is a skip (nothing written).
func (r *importRun) write(ctx context.Context, tx ImportTx, p *ldapdir.Person) (reason, userID string, created bool, err error) {
	links, err := tx.LinksByUIDs(ctx, r.tenantID, r.c.ID, []string{p.UID})
	if err != nil {
		return "", "", false, err
	}
	if l, ok := links[p.UID]; ok {
		return r.refresh(ctx, tx, &l, p)
	}
	switch _, err := tx.UserByEmail(ctx, r.tenantID, p.Email); {
	case err == nil:
		return ReasonEmailInUse, "", false, nil
	case !errors.Is(err, store.ErrNotFound):
		return "", "", false, err
	}
	u := store.User{ID: store.NewID(), TenantID: r.tenantID, Email: p.Email, Status: "imported",
		DisplayName: p.DisplayName, FirstName: p.FirstName, LastName: p.LastName, DisplayNameExplicit: p.DisplayNameExplicit}
	if err := tx.InsertUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return ReasonEmailInUse, "", false, nil
		}
		return "", "", false, err
	}
	if err := tx.UpsertLink(ctx, r.link(u.ID, p)); err != nil {
		return "", "", false, err
	}
	return "", u.ID, true, nil
}

// refresh handles an entry already linked to this connection: the profile
// follows the directory only while the user is still imported (the e-mail
// only when no other tenant user holds it); after activation the platform
// profile is authoritative and the entry is skipped.
func (r *importRun) refresh(ctx context.Context, tx ImportTx, l *store.DirectoryLink, p *ldapdir.Person) (reason, userID string, created bool, err error) {
	u, err := tx.User(ctx, r.tenantID, l.UserID)
	if err != nil {
		return "", "", false, err
	}
	if u.Status != "imported" {
		return ReasonAlreadyActive, "", false, nil
	}
	prof := store.ImportedProfile{Email: u.Email, DisplayName: p.DisplayName, FirstName: p.FirstName, LastName: p.LastName,
		DisplayNameExplicit: p.DisplayNameExplicit}
	if !strings.EqualFold(p.Email, u.Email) {
		switch other, err := tx.UserByEmail(ctx, r.tenantID, p.Email); {
		case errors.Is(err, store.ErrNotFound):
			prof.Email = p.Email
		case err != nil:
			return "", "", false, err
		case other.ID == u.ID:
			prof.Email = p.Email
		}
	}
	if err := tx.UpdateImportedUser(ctx, r.tenantID, u.ID, prof); err != nil {
		return "", "", false, err
	}
	if err := tx.UpsertLink(ctx, r.link(u.ID, p)); err != nil {
		return "", "", false, err
	}
	return "", u.ID, false, nil
}

// link is the link row as of this import (UpsertLink keeps first_imported_at
// of an existing row).
func (r *importRun) link(userID string, p *ldapdir.Person) store.DirectoryLink {
	connID := r.c.ID
	l := store.DirectoryLink{UserID: userID, TenantID: r.tenantID, ConnectionID: &connID, ConnectionName: r.c.Name,
		DirectoryUID: p.UID, DirectoryDN: p.DN, FirstImportedAt: r.now, LastImportedAt: r.now}
	if r.actor.UserID != "" {
		by := r.actor.UserID
		l.ImportedBy = &by
	}
	return l
}

func (r *importRun) skip(uid, reason string) {
	r.res.Skipped = append(r.res.Skipped, ImportIssue{UID: uid, Reason: reason})
}

// fail reports a directory error in the closed failed vocabulary.
func (r *importRun) fail(uid string, err error) {
	if errors.Is(err, ldapdir.ErrTimeout) {
		r.failReason(uid, ReasonTimeout)
		return
	}
	r.failReason(uid, ReasonDirectoryError)
}

func (r *importRun) failReason(uid, reason string) {
	r.res.Failed = append(r.res.Failed, ImportIssue{UID: uid, Reason: reason})
}

// details is the directory_imported payload: counts and user ids only, never
// e-mails, names, DNs or directory uids (D14).
func (r *importRun) details(connID string) map[string]any {
	ids := func(items []ImportItem) []string {
		out := make([]string, 0, len(items))
		for _, it := range items {
			out = append(out, it.UserID)
		}
		return out
	}
	return map[string]any{
		"connection_id": connID,
		"created":       len(r.res.Created), "updated": len(r.res.Updated),
		"skipped": len(r.res.Skipped), "failed": len(r.res.Failed),
		"created_user_ids": ids(r.res.Created), "updated_user_ids": ids(r.res.Updated),
	}
}

// openBound opens a session, checks TLS and binds (zeroing pw). On error the
// session is closed and the closed ldapdir error returned.
func (s *Service) openBound(ctx context.Context, c *store.DirectoryConnection, pw []byte) (ldapdir.Session, error) {
	dial := s.d.Config.DialTimeout
	if dial <= 0 {
		dial = ldapdir.DefaultDialTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, dial+searchGrace)
	defer cancel()
	sess, err := s.d.Directory.Open(ctx, ldapdir.ConnParams{
		URL: c.URL, TLSMode: c.TLSMode, CAPEM: c.CAPEM, AllowTLS12: c.AllowTLS12, DialTimeout: s.d.Config.DialTimeout,
	})
	if err != nil {
		return nil, closedDirErr(err)
	}
	if c.TLSMode != ldapdir.TLSModePlain {
		if st, ok := sess.TLSState(); !ok || !st.HandshakeComplete {
			_ = sess.Close()
			return nil, ldapdir.ErrTLS
		}
	}
	if err := sess.Bind(ctx, c.BindDN, pw); err != nil {
		_ = sess.Close()
		return nil, closedDirErr(err)
	}
	return sess, nil
}

// reopen replaces a session lost mid-import.
func (s *Service) reopen(ctx context.Context, c *store.DirectoryConnection, tenantID, connID string) (ldapdir.Session, error) {
	pw, err := s.testPassword(&Input{}, c, tenantID, connID)
	if err != nil {
		return nil, err
	}
	defer clear(pw)
	return s.openBound(ctx, c, pw)
}

// emitImported writes directory_imported (outcome ok/failed).
func (s *Service) emitImported(actor *tenantctx.Actor, tenantID, connID, outcome, reason string, details map[string]any) {
	e := audit.Event{Type: audit.DirectoryImported, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID,
		SubjectKind: subjectKind, SubjectID: connID, Outcome: outcome, Reason: reason, Details: details}
	s.emit(&e)
}
