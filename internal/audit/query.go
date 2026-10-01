package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// Querier reads the audit hypertable (database or in-memory).
type Querier interface {
	// QueryAudit serves the legacy cursor path: newest first, strictly after
	// the (cursor, cursorID) position.
	QueryAudit(ctx context.Context, tenantID, userID, eventType string, from, to, cursor time.Time, cursorID int64, limit int) ([]store.AuditRow, error)
	// PageAudit counts and pages the events matching f (list contract).
	PageAudit(ctx context.Context, tenantID string, f store.AuditPageFilter, req listquery.Request) ([]store.AuditRow, int, listquery.Request, error)
}

// Filter selects events; zero values mean "any".
type Filter struct {
	UserID    string
	EventType string
	From, To  time.Time
	Cursor    string // opaque; from a previous page
	Limit     int    // ≤ 200, default 50
}

// Item is one event as returned to administrators.
type Item struct {
	ID            string          `json:"id"`
	TS            time.Time       `json:"ts"`
	EventType     string          `json:"event_type"`
	ActorUserID   *string         `json:"actor_user_id"`
	ActorKind     string          `json:"actor_kind"`
	SubjectKind   string          `json:"subject_kind,omitempty"`
	SubjectID     *string         `json:"subject_id"`
	Outcome       string          `json:"outcome"`
	Reason        string          `json:"reason,omitempty"`
	CorrelationID string          `json:"correlation_id,omitempty"`
	Details       json.RawMessage `json:"details"`
}

// Page is a cursor-paged result (legacy path). Total counts every event
// matching the filter (the cursor aside).
type Page struct {
	Items      []Item `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
	Total      int    `json:"total"`
}

// ErrFilter is returned for malformed filters.
var ErrFilter = errors.New("audit: invalid filter")

// ErrSpan refuses a window wider than store.MaxAuditSpan; it names the from
// parameter (validation_failed {param: from}) and never carries the value.
var ErrSpan = &listquery.Error{Param: "from"}

// checkSpan refuses an explicit from more than store.MaxAuditSpan before to
// (now when absent).
func checkSpan(from, to, now time.Time) error {
	if to.IsZero() {
		to = now
	}
	if !from.IsZero() && to.Sub(from) > store.MaxAuditSpan {
		return ErrSpan
	}
	return nil
}

// validate checks the filter vocabulary and the time range.
func (f Filter) validate() error {
	if f.EventType != "" {
		if _, ok := known[EventType(f.EventType)]; !ok {
			return ErrFilter
		}
	}
	if !f.From.IsZero() && !f.To.IsZero() && f.To.Before(f.From) {
		return ErrFilter
	}
	return nil
}

// parseCursor reads a legacy cursor: "<ts unix nanos>.<id>" from this
// release, or "<ts unix nanos>" from the previous one (id 0).
func parseCursor(c string) (time.Time, int64, error) {
	tsPart, idPart, hasID := strings.Cut(c, ".")
	n, err := strconv.ParseInt(tsPart, 10, 64)
	if err != nil {
		return time.Time{}, 0, ErrFilter
	}
	var id int64
	if hasID {
		if id, err = strconv.ParseInt(idPart, 10, 64); err != nil || id < 1 {
			return time.Time{}, 0, ErrFilter
		}
	}
	return time.Unix(0, n), id, nil
}

// Query lists events of one tenant, newest first, scoped by the caller's
// tenant id (never by a client-supplied one). It is the legacy cursor path
// (one release, go-tangra specs/032-server-side-tables D7); the cursor
// carries the id tie-breaker so events sharing a timestamp are never skipped.
// An explicit window wider than store.MaxAuditSpan is ErrSpan.
func Query(ctx context.Context, q Querier, tenantID string, f Filter) (Page, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if err := f.validate(); err != nil {
		return Page{}, err
	}
	if err := checkSpan(f.From, f.To, time.Now()); err != nil {
		return Page{}, err
	}
	var (
		cursor   time.Time
		cursorID int64
	)
	if f.Cursor != "" {
		var err error
		if cursor, cursorID, err = parseCursor(f.Cursor); err != nil {
			return Page{}, err
		}
	}
	// An absent upper bound means "up to now" (the SQL compares ts <= to);
	// an absent lower bound is the default window before it, as on the page
	// path, so the total (counted on every page) stays bounded on the
	// hypertable (research D6).
	to, from := f.To, f.From
	if to.IsZero() {
		to = time.Now().Add(time.Minute)
	}
	if from.IsZero() {
		from = to.Add(-store.AuditWindow)
	}
	rows, err := q.QueryAudit(ctx, tenantID, f.UserID, f.EventType, from, to, cursor, cursorID, f.Limit+1)
	if err != nil {
		return Page{}, err
	}
	_, total, _, err := q.PageAudit(ctx, tenantID, store.AuditPageFilter{UserID: f.UserID, EventType: f.EventType, From: from, To: to},
		listquery.Request{Page: 1, PageSize: 1, Sort: "ts", Order: listquery.Desc})
	if err != nil {
		return Page{}, err
	}
	page := Page{Items: []Item{}, Total: total}
	for i, r := range rows {
		if i == f.Limit {
			last := rows[i-1]
			page.NextCursor = strconv.FormatInt(last.TS.UnixNano(), 10) + "." + strconv.FormatInt(last.ID, 10)
			break
		}
		page.Items = append(page.Items, item(r))
	}
	return page, nil
}

// List pages the events of one tenant (list contract). Without From/To it
// covers the last store.AuditWindow before now; To defaults to now and From
// to To minus the window (research D6), so the exact count stays bounded.
// An explicit window wider than store.MaxAuditSpan is ErrSpan.
func List(ctx context.Context, q Querier, tenantID string, f Filter, req listquery.Request, now time.Time) (listquery.Page[Item], error) {
	if err := checkSpan(f.From, f.To, now); err != nil {
		return listquery.Page[Item]{}, err
	}
	if f.To.IsZero() {
		f.To = now
	}
	if f.From.IsZero() {
		f.From = f.To.Add(-store.AuditWindow)
	}
	if err := f.validate(); err != nil {
		return listquery.Page[Item]{}, err
	}
	rows, total, applied, err := q.PageAudit(ctx, tenantID, store.AuditPageFilter{UserID: f.UserID, EventType: f.EventType, From: f.From, To: f.To}, req)
	if err != nil {
		return listquery.Page[Item]{}, err
	}
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, item(r))
	}
	return listquery.NewPage(items, total, applied), nil
}

func item(r store.AuditRow) Item {
	details := r.Details
	if len(details) == 0 {
		details = json.RawMessage("{}")
	}
	return Item{ID: strconv.FormatInt(r.ID, 10), TS: r.TS, EventType: r.EventType, ActorUserID: r.ActorUserID, ActorKind: r.ActorKind, SubjectKind: r.SubjectKind,
		SubjectID: r.SubjectID, Outcome: r.Outcome, Reason: r.Reason, CorrelationID: r.CorrelationID, Details: details}
}
