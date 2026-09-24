package directory

import (
	"context"
	"crypto/tls"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/cache"
	"github.com/go-freya/freya/services/auth/internal/ldapdir"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

// Test steps (contracts §A TestResult.step).
const (
	StepConnect    = "connect"
	StepTLS        = "tls"
	StepBind       = "bind"
	StepSearchBase = "search_base"
)

// rateWindow is the per-tenant window for directory.rate_per_minute, shared
// by connection tests and searches.
const rateWindow = time.Minute

// persistTimeout bounds recording last_test after the caller's ctx may have
// expired (a timed-out test is still an outcome worth keeping).
const persistTimeout = 5 * time.Second

// outcomes is the last_test_outcome vocabulary (data-model); any other
// reason is stored as directory_error.
var outcomes = map[string]bool{
	"ok": true, "unreachable": true, "target_refused": true, "timeout": true, "tls_failed": true,
	"invalid_credentials": true, "base_not_found": true, "directory_error": true,
}

var (
	errUnseal  = errors.New("directory: the stored bind credential cannot be used")
	errPersist = errors.New("directory: recording the test result failed")
	errLimiter = errors.New("directory: rate limiter unavailable")
)

// Test runs open → TLS → bind → base check against a connection. A zero
// Input with connID tests the saved connection and persists last_test (the
// saved-connection route). Otherwise in is an unsaved connection; with connID
// the omitted fields and, when bind_password is omitted, the stored password
// come from that connection of the same tenant, and nothing is persisted.
// A failing step is a result; errors are refusals before any dial.
func (s *Service) Test(ctx context.Context, actor tenantctx.Actor, tenantID string, in Input, connID string) (TestResult, error) { //nolint:gocritic // Input by value is the HTTP-facing signature
	if connID != "" && reflect.ValueOf(in).IsZero() {
		return s.TestSaved(ctx, actor, tenantID, connID)
	}
	return s.test(ctx, &actor, tenantID, &in, connID, false)
}

// TestSaved tests a stored connection with its stored settings and password
// and records the outcome as last_test.
func (s *Service) TestSaved(ctx context.Context, actor tenantctx.Actor, tenantID, connID string) (TestResult, error) { //nolint:gocritic // actor by value is the HTTP-facing signature
	return s.test(ctx, &actor, tenantID, &Input{}, connID, true)
}

func (s *Service) test(ctx context.Context, actor *tenantctx.Actor, tenantID string, in *Input, connID string, saved bool) (TestResult, error) {
	if err := s.allow(ctx, tenantID); err != nil {
		if errors.Is(err, ErrRateLimited) {
			s.emitTested(actor, tenantID, connID, "refused", ErrRateLimited.Error(), "")
		}
		return TestResult{}, err
	}
	maxSize, maxTime := s.maxLimits()
	c := store.DirectoryConnection{TenantID: tenantID,
		SizeLimit: min(defaultSizeLimit, maxSize), TimeLimitSeconds: min(defaultTimeLimit, maxTime)}
	if connID != "" {
		stored, err := s.lookup(ctx, actor, tenantID, connID)
		if err != nil {
			return TestResult{}, err
		}
		c = stored
	}
	old := c
	apply(&c, in)
	if connID != "" && in.BindPassword == nil && targetChanged(&old, &c) {
		s.refused(audit.DirectoryConnectionTested, actor, tenantID, connID, errCredentialRequired)
		return TestResult{}, errCredentialRequired
	}
	targetErr, err := s.checkTestTarget(&c)
	if err != nil {
		s.refused(audit.DirectoryConnectionTested, actor, tenantID, connID, err)
		return TestResult{}, err
	}
	pw, err := s.testPassword(in, &c, tenantID, connID)
	if err != nil {
		return TestResult{}, err
	}
	defer clear(pw)

	var res TestResult
	if targetErr != nil {
		res = TestResult{Step: StepConnect, Reason: ldapdir.Reason(targetErr)}
	} else {
		res = s.run(ctx, &c, pw)
	}
	outcome := "ok"
	if !res.OK {
		outcome = res.Reason
		if !outcomes[outcome] {
			outcome = "directory_error"
		}
	}
	if saved {
		pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), persistTimeout)
		defer cancel()
		if err := s.d.Store.SetDirectoryConnectionTest(pctx, tenantID, connID, outcome, s.d.Now()); err != nil {
			return TestResult{}, errPersist
		}
	}
	if res.OK {
		s.emitTested(actor, tenantID, connID, "ok", "", "")
	} else {
		s.emitTested(actor, tenantID, connID, "failed", res.Reason, res.Step)
	}
	return res, nil
}

// allow counts one directory operation against the tenant's per-minute
// limit. A limiter failure refuses the operation (fail closed: every test or
// search is an outbound connection).
func (s *Service) allow(ctx context.Context, tenantID string) error {
	limit := s.d.Config.RatePerMinute
	if s.d.Cache == nil || limit <= 0 {
		return nil
	}
	n, err := s.d.Cache.Count(ctx, cache.RateKey("directory", tenantID), rateWindow)
	if err != nil {
		return errLimiter
	}
	if n > int64(limit) {
		return ErrRateLimited
	}
	return nil
}

// checkTestTarget validates what a test needs before dialling. A target the
// policy refuses is not an error but a failed connect step, returned as
// targetErr once the rest of the input is known to be valid.
func (s *Service) checkTestTarget(c *store.DirectoryConnection) (targetErr, err error) {
	switch c.TLSMode {
	case ldapdir.TLSModeLDAPS, ldapdir.TLSModeStartTLS, ldapdir.TLSModePlain:
	default:
		return nil, ErrValidation
	}
	if err := s.checkTarget(c.URL, c.TLSMode); err != nil {
		if !errors.Is(err, ldapdir.ErrTargetRefused) {
			return nil, err
		}
		targetErr = err
	}
	if c.CAPEM != "" {
		if _, err := ldapdir.ParseCA(c.CAPEM); err != nil {
			return nil, ldapdir.ErrInvalidCA
		}
	}
	if !validDN(c.BindDN) || !validDN(c.BaseDN) {
		return nil, ErrValidation
	}
	return targetErr, nil
}

// testPassword returns the typed password, or the stored one unsealed under
// ldap-bind:<tenant>:<connID>. There is no anonymous bind.
func (s *Service) testPassword(in *Input, c *store.DirectoryConnection, tenantID, connID string) ([]byte, error) {
	if in.BindPassword != nil {
		pw := *in.BindPassword
		if strings.TrimSpace(pw) == "" || len(pw) > maxPasswordLen {
			return nil, ErrValidation
		}
		return []byte(pw), nil
	}
	if connID == "" || len(c.BindPasswordEnc) == 0 {
		return nil, ErrValidation
	}
	pw, err := s.d.Envelope.Decrypt(c.BindPasswordEnc, sealAD(tenantID, connID))
	if err != nil {
		return nil, errUnseal
	}
	return pw, nil
}

// run performs the steps in order and stops at the first failure. Bind
// zeroes pw. The session is always closed.
func (s *Service) run(ctx context.Context, c *store.DirectoryConnection, pw []byte) TestResult {
	start := time.Now()
	fail := func(step string, err error) TestResult {
		return TestResult{Step: step, Reason: ldapdir.Reason(err), DurationMS: time.Since(start).Milliseconds()}
	}
	dial := s.d.Config.DialTimeout
	if dial <= 0 {
		dial = ldapdir.DefaultDialTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, dial+time.Duration(c.TimeLimitSeconds)*time.Second)
	defer cancel()

	sess, err := s.d.Directory.Open(ctx, ldapdir.ConnParams{
		URL: c.URL, TLSMode: c.TLSMode, CAPEM: c.CAPEM, AllowTLS12: c.AllowTLS12, DialTimeout: s.d.Config.DialTimeout,
	})
	if err != nil {
		if errors.Is(err, ldapdir.ErrTLS) {
			return fail(StepTLS, err)
		}
		return fail(StepConnect, err)
	}
	defer func() { _ = sess.Close() }()

	var info *TLSInfo
	if c.TLSMode != ldapdir.TLSModePlain {
		state, ok := sess.TLSState()
		if !ok || !state.HandshakeComplete {
			return fail(StepTLS, ldapdir.ErrTLS)
		}
		info = tlsInfo(&state)
	}
	if err := sess.Bind(ctx, c.BindDN, pw); err != nil {
		return fail(StepBind, err)
	}
	if err := sess.BaseExists(ctx, c.BaseDN); err != nil {
		return fail(StepSearchBase, err)
	}
	return TestResult{OK: true, TLS: info, DurationMS: time.Since(start).Milliseconds()}
}

func tlsInfo(st *tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{Version: tls.VersionName(st.Version)}
	if len(st.PeerCertificates) > 0 {
		info.PeerSubject = st.PeerCertificates[0].Subject.String()
	}
	return info
}

// emitTested writes directory_connection_tested: outcome ok/failed/refused,
// the closed reason, the failing step and the connection id when one was used.
func (s *Service) emitTested(actor *tenantctx.Actor, tenantID, connID, outcome, reason, step string) {
	e := audit.Event{Type: audit.DirectoryConnectionTested, TenantID: tenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID,
		Outcome: outcome, Reason: reason}
	details := map[string]any{}
	if step != "" {
		details["step"] = step
	}
	if connID != "" {
		e.SubjectKind, e.SubjectID = subjectKind, connID
		details["connection_id"] = connID
	}
	if len(details) > 0 {
		e.Details = details
	}
	s.emit(&e)
}
