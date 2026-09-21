package grpcapi

import (
	"context"
	"errors"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/go-freya/freya/authn"
	authv1 "github.com/go-freya/freya/services/auth/api/proto/auth/v1"
	"github.com/go-freya/freya/services/auth/internal/audit"
	"github.com/go-freya/freya/services/auth/internal/session"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/go-freya/freya/services/auth/internal/token"
	"github.com/go-freya/freya/services/auth/pkg/authclient"
)

// SessionsServer serves the revocation feed and introspection.
type SessionsServer struct {
	authv1.UnimplementedSessionsServer
	Sessions *session.Manager
	Tokens   *token.Issuer
	Audit    *audit.Writer
	Poll     time.Duration // Watch poll interval (default 5s)
}

func secs(n int64) time.Duration { return time.Duration(n) * time.Second }

// cursor encodes the last delivered timestamp in nanoseconds.
func parseCursor(c string) (time.Time, error) {
	if c == "" {
		return time.Now().Add(-session.RevocationRetention), nil
	}
	n, err := strconv.ParseInt(c, 10, 64)
	if err != nil {
		return time.Time{}, status.Error(codes.InvalidArgument, "malformed cursor")
	}
	return time.Unix(0, n), nil
}

func toProto(r store.Revocation) *authv1.Revocation {
	return &authv1.Revocation{Ts: timestamppb.New(r.TS), Kind: r.Kind, SubjectId: r.SubjectID, TenantId: r.TenantID, Reason: r.Reason}
}

// RevokedSince pages the feed after the cursor.
func (s *SessionsServer) RevokedSince(ctx context.Context, req *authv1.RevokedSinceRequest) (*authv1.RevokedSinceResponse, error) {
	since, err := parseCursor(req.GetCursor())
	if err != nil {
		return nil, err
	}
	limit := int(req.GetLimit())
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	entries, err := s.Sessions.Since(ctx, since, limit)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "feed unavailable")
	}
	out := &authv1.RevokedSinceResponse{NextCursor: req.GetCursor()}
	if req.GetCursor() == "" {
		out.NextCursor = strconv.FormatInt(since.UnixNano(), 10)
	}
	for _, e := range entries {
		out.Revocations = append(out.Revocations, toProto(e))
		out.NextCursor = strconv.FormatInt(e.TS.UnixNano(), 10)
	}
	return out, nil
}

// Watch streams feed entries as they appear until the client goes away.
func (s *SessionsServer) Watch(req *authv1.WatchRequest, stream authv1.Sessions_WatchServer) error {
	since, err := parseCursor(req.GetCursor())
	if err != nil {
		return err
	}
	poll := s.Poll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		entries, err := s.Sessions.Since(stream.Context(), since, 1000)
		if err != nil {
			return status.Error(codes.Unavailable, "feed unavailable")
		}
		for _, e := range entries {
			if err := stream.Send(toProto(e)); err != nil {
				return err
			}
			since = e.TS
		}
		select {
		case <-stream.Context().Done():
			return nil
		case <-t.C:
		}
	}
}

// Introspect verifies a token and reports its state; every call is audited
// with the calling service as actor.
func (s *SessionsServer) Introspect(ctx context.Context, req *authv1.IntrospectRequest) (*authv1.IntrospectResponse, error) {
	c, err := s.Tokens.Verify(req.GetToken())
	resp := &authv1.IntrospectResponse{}
	svc := ""
	if p, ok := authn.FromContext(ctx); ok {
		svc = p.ID.String()
	}
	if err != nil {
		resp.Reason = "invalid"
		var unknown *authclient.UnknownKeyError
		if errors.As(err, &unknown) {
			resp.Reason = "invalid"
		} else if errors.Is(err, errExpired(err)) {
			resp.Reason = "expired"
		}
		s.emit(audit.Event{Type: audit.AuthzDenied, TenantID: "00000000-0000-0000-0000-000000000000", ActorKind: "service", ActorService: svc, Outcome: "refused", Reason: "introspect_" + resp.Reason})
		return resp, nil
	}
	resp.UserId, resp.TenantId, resp.SessionId, resp.Roles = c.Subject, c.TenantID, c.SessionID, c.Roles
	resp.ExpiresAt = timestamppb.New(c.ExpiresAt.Time)
	entries, err := s.Sessions.Since(ctx, c.IssuedAt.Time.Add(-time.Second), 1000)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "feed unavailable")
	}
	resp.Active = true
	for _, e := range entries {
		if e.TS.Unix() < c.IssuedAt.Time.Unix() {
			continue
		}
		if (e.Kind == "session" && e.SubjectID == c.SessionID) || (e.Kind == "user" && e.SubjectID == c.Subject) || (e.Kind == "tenant" && e.SubjectID == c.TenantID) {
			resp.Active, resp.Reason = false, "revoked"
			break
		}
	}
	outcome := "ok"
	if !resp.Active {
		outcome = "refused"
	}
	s.emit(audit.Event{Type: audit.AuthzDenied, TenantID: c.TenantID, ActorKind: "service", ActorService: svc, SubjectKind: "session", SubjectID: c.SessionID, Outcome: outcome, Reason: "introspect_" + orActive(resp.Reason)})
	return resp, nil
}

func orActive(r string) string {
	if r == "" {
		return "active"
	}
	return r
}

// errExpired returns err itself when it describes an expired token so the
// caller can use errors.Is uniformly.
func errExpired(err error) error {
	if err != nil && contains(err.Error(), "expired") {
		return err
	}
	return errors.New("not-expired")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func (s *SessionsServer) emit(e audit.Event) {
	if s.Audit != nil {
		_ = s.Audit.Emit(e)
	}
}
