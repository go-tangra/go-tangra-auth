package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-freya/freya/services/auth/internal/store"
)

// EventType is the closed vocabulary of application audit events.
type EventType string

// Event types (data-model.md).
const (
	SigninOK             EventType = "signin_ok"
	SigninFailed         EventType = "signin_failed"
	Lockout              EventType = "lockout"
	Signout              EventType = "signout"
	MFAEnrolled          EventType = "mfa_enrolled"
	MFARemoved           EventType = "mfa_removed"
	RecoveryCodesRegen   EventType = "recovery_codes_regenerated"
	PasswordChanged      EventType = "password_changed"
	RecoveryRequested    EventType = "recovery_requested"
	RecoveryCompleted    EventType = "recovery_completed"
	InviteCreated        EventType = "invite_created"
	InviteAccepted       EventType = "invite_accepted"
	InviteRevoked        EventType = "invite_revoked"
	RoleCreated          EventType = "role_created"
	RoleUpdated          EventType = "role_updated"
	RoleDeleted          EventType = "role_deleted"
	RoleAssigned         EventType = "role_assigned"
	RoleRevoked          EventType = "role_revoked"
	PermissionRegistered EventType = "permission_registered"
	UserDeactivated      EventType = "user_deactivated"
	UserReactivated      EventType = "user_reactivated"
	SessionRevoked       EventType = "session_revoked"
	TenantCreated        EventType = "tenant_created"
	TenantSuspended      EventType = "tenant_suspended"
	TenantReactivated    EventType = "tenant_reactivated"
	OperatorGrantCreated EventType = "operator_grant_created"
	OperatorGrantUsed    EventType = "operator_grant_used"
	ClientRegistered     EventType = "client_registered"
	PolicyUpdated        EventType = "policy_updated"
	CrossTenantRefused   EventType = "cross_tenant_refused"
	AuthzDenied          EventType = "authz_denied"
	TokenExchanged       EventType = "token_exchanged"
	// Feature 004: groups and profiles.
	GroupCreated       EventType = "group_created"
	GroupUpdated       EventType = "group_updated"
	GroupDeleted       EventType = "group_deleted"
	GroupMemberAdded   EventType = "group_member_added"
	GroupMemberRemoved EventType = "group_member_removed"
	GroupRoleGranted   EventType = "group_role_granted"
	GroupRoleRevoked   EventType = "group_role_revoked"
	ProfileUpdated     EventType = "profile_updated"
	AvatarUpdated      EventType = "avatar_updated"
	AvatarRemoved      EventType = "avatar_removed"
)

var known = map[EventType]struct{}{}

func init() {
	for _, t := range []EventType{SigninOK, SigninFailed, Lockout, Signout, MFAEnrolled, MFARemoved, RecoveryCodesRegen, PasswordChanged,
		RecoveryRequested, RecoveryCompleted, InviteCreated, InviteAccepted, InviteRevoked, RoleCreated, RoleUpdated, RoleDeleted, RoleAssigned,
		RoleRevoked, PermissionRegistered, UserDeactivated, UserReactivated, SessionRevoked, TenantCreated, TenantSuspended, TenantReactivated,
		OperatorGrantCreated, OperatorGrantUsed, ClientRegistered, PolicyUpdated, CrossTenantRefused, AuthzDenied, TokenExchanged,
		GroupCreated, GroupUpdated, GroupDeleted, GroupMemberAdded, GroupMemberRemoved, GroupRoleGranted, GroupRoleRevoked, ProfileUpdated, AvatarUpdated, AvatarRemoved} {
		known[t] = struct{}{}
	}
}

// Event is one application audit record before persistence.
type Event struct {
	Type          EventType
	TenantID      string
	ActorUserID   string
	ActorKind     string // user | operator | service | system
	ActorService  string
	SubjectKind   string
	SubjectID     string
	Outcome       string // ok | refused | failed
	Reason        string
	OriginIPHash  string
	UserAgent     string
	CorrelationID string
	TraceID       string
	Details       map[string]any
}

// Inserter persists batches (implemented by the store; faked in tests).
type Inserter interface {
	InsertAuditRows(ctx context.Context, rows []store.AuditRow) error
}

// Writer buffers events and writes them in batches; Emit never blocks.
type Writer struct {
	ins     Inserter
	ch      chan store.AuditRow
	wg      sync.WaitGroup
	mu      sync.Mutex
	closed  bool
	dropped int64
	onError func(error)
	flushCh chan chan struct{}
}

// forbidden detail keys are redacted defensively even though callers never pass secrets.
// PII keys (feature 004) are redacted too: events carry field names, never values.
var forbidden = []string{"password", "secret", "token", "key", "code", "cookie", "authorization", "phone", "first_name", "last_name", "display_name", "email_address"}

// NewWriter starts the batch writer (queue 10k, batch 200 or 500ms).
func NewWriter(ins Inserter, onError func(error)) *Writer {
	w := &Writer{ins: ins, ch: make(chan store.AuditRow, 10000), onError: onError, flushCh: make(chan chan struct{})}
	if w.onError == nil {
		w.onError = func(error) {}
	}
	w.wg.Add(1)
	go w.run()
	return w
}

// Validate checks the vocabulary and required fields.
func Validate(e Event) error {
	if _, ok := known[e.Type]; !ok {
		return fmt.Errorf("audit: unknown event type %q", e.Type)
	}
	if e.TenantID == "" {
		return errors.New("audit: tenant_id is required")
	}
	switch e.Outcome {
	case "ok", "refused", "failed":
	default:
		return fmt.Errorf("audit: outcome %q", e.Outcome)
	}
	switch e.ActorKind {
	case "user", "operator", "service", "system":
	default:
		return fmt.Errorf("audit: actor_kind %q", e.ActorKind)
	}
	return nil
}

// Row converts an event to a store row, redacting forbidden detail keys.
func Row(e Event, now time.Time) (store.AuditRow, error) {
	if err := Validate(e); err != nil {
		return store.AuditRow{}, err
	}
	details := map[string]any{}
	for k, v := range e.Details {
		lk := strings.ToLower(k)
		redact := false
		for _, f := range forbidden {
			if strings.Contains(lk, f) {
				redact = true
			}
		}
		if redact {
			details[k] = "[REDACTED]"
		} else {
			details[k] = v
		}
	}
	js, err := json.Marshal(details)
	if err != nil {
		return store.AuditRow{}, err
	}
	r := store.AuditRow{TS: now, TenantID: e.TenantID, EventType: string(e.Type), ActorKind: e.ActorKind, ActorService: e.ActorService,
		SubjectKind: e.SubjectKind, Outcome: e.Outcome, Reason: e.Reason, OriginIPHash: e.OriginIPHash, UserAgent: e.UserAgent,
		CorrelationID: e.CorrelationID, TraceID: e.TraceID, Details: js}
	if e.ActorUserID != "" {
		v := e.ActorUserID
		r.ActorUserID = &v
	}
	if e.SubjectID != "" {
		v := e.SubjectID
		r.SubjectID = &v
	}
	return r, nil
}

// Emit validates and queues an event.
func (w *Writer) Emit(e Event) error {
	row, err := Row(e, time.Now())
	if err != nil {
		return err
	}
	w.mu.Lock()
	closed := w.closed
	w.mu.Unlock()
	if closed {
		w.dropped++
		return errors.New("audit: writer closed")
	}
	select {
	case w.ch <- row:
	default:
		w.mu.Lock()
		w.dropped++
		w.mu.Unlock()
		w.onError(errors.New("audit: queue full, event dropped"))
	}
	return nil
}

// Flush writes everything queued so far and returns when it is stored (tests
// and graceful shutdown paths that need to observe their own events).
func (w *Writer) Flush() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.mu.Unlock()
	done := make(chan struct{})
	w.flushCh <- done
	<-done
}

// Dropped returns the number of dropped events.
func (w *Writer) Dropped() int64 { w.mu.Lock(); defer w.mu.Unlock(); return w.dropped }

func (w *Writer) run() {
	defer w.wg.Done()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	buf := make([]store.AuditRow, 0, 200)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := w.ins.InsertAuditRows(ctx, buf); err != nil {
			w.onError(err)
		}
		cancel()
		buf = buf[:0]
	}
	for {
		select {
		case r, ok := <-w.ch:
			if !ok {
				flush()
				return
			}
			buf = append(buf, r)
			if len(buf) >= 200 {
				flush()
			}
		case <-t.C:
			flush()
		case done := <-w.flushCh:
			// Drain what is already queued before flushing.
			for len(w.ch) > 0 {
				buf = append(buf, <-w.ch)
			}
			flush()
			close(done)
		}
	}
}

// Close drains and stops the writer.
func (w *Writer) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	close(w.ch)
	w.mu.Unlock()
	w.wg.Wait()
}
