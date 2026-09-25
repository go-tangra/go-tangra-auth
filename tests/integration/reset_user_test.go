//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-auth/v4/internal/app"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// TestResetUser covers `authsvc reset-user`: credentials, MFA, recovery codes
// and sessions are cleared, the old password stops working, and the printed
// invitation restores the account with its roles.
func TestResetUser(t *testing.T) {
	e := Start(t)
	ctx := context.Background()
	const em, oldPW, newPW = "locked@acme.test", "the-old-long-password", "a-brand-new-long-password"
	tid, uid := e.Seed("acme", em, oldPW, "")
	role := store.Role{ID: store.NewID(), TenantID: tid, Slug: "auditor", DisplayName: "auditor", Builtin: true}
	if err := e.App.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		if err := store.InsertRole(ctx, tx, role); err != nil {
			return err
		}
		if err := store.ReplaceRoleBindings(ctx, tx, tid, uid, uid, []string{role.ID}); err != nil {
			return err
		}
		if err := store.SetMFA(ctx, tx, tid, uid, true, []byte("sealed-seed")); err != nil {
			return err
		}
		return store.ReplaceRecoveryCodes(ctx, tx, tid, uid, []string{"h1", "h2"})
	}); err != nil {
		t.Fatal(err)
	}
	// An accepted user holds these tuples; accepting the reset invitation must
	// not fail on writing them again.
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	if err := e.App.Authz.Write(sys, tid, []authz.Tuple{authz.MembershipTuple(tid, uid, "member"), authz.RoleAssignmentTuple(tid, "auditor", uid)}, nil); err != nil {
		t.Fatal(err)
	}

	res, err := e.App.ResetUser(ctx, "acme", em)
	if err != nil {
		t.Fatal(err)
	}
	if res.UserID != uid || len(res.Roles) != 1 || res.Roles[0] != "auditor" || !strings.Contains(res.AcceptURL, "/console/invite/accept?token=") {
		t.Fatalf("unexpected result: %+v", res)
	}
	var status string
	var mfa bool
	var pwNull bool
	var codes int
	if err := e.App.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "SELECT status, mfa_enabled, password_hash IS NULL FROM users WHERE id=$1", uid).Scan(&status, &mfa, &pwNull); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT count(*) FROM recovery_codes WHERE user_id=$1", uid).Scan(&codes)
	}); err != nil {
		t.Fatal(err)
	}
	if status != "invited" || mfa || !pwNull || codes != 0 {
		t.Fatalf("credentials not cleared: status=%s mfa=%v pwNull=%v codes=%d", status, mfa, pwNull, codes)
	}
	if code := e.Browser().SignIn("acme", em, oldPW); code == 200 {
		t.Fatal("the old password must stop working after a reset")
	}
	if mail := e.LastMail(em); !strings.Contains(mail, res.AcceptURL) {
		t.Fatalf("reset mail missing the accept link: %q", mail)
	}
	if r := e.LastSend(em); r.GetTemplateKey() != "auth.account_reset" || r.GetVariables()["valid_for"] != "7 days" {
		t.Fatalf("reset send %+v", r)
	}

	tok := res.AcceptURL[strings.Index(res.AcceptURL, "token=")+6:]
	b := e.Browser()
	code, out := b.JSON(http.MethodPost, "/api/v1/invitations/accept", map[string]string{"token": tok, "display_name": "Locked", "password": newPW})
	if code != 200 || out["signed_in"] != true {
		t.Fatalf("accept after reset: %d %v", code, out)
	}
	code, out = b.JSON(http.MethodGet, "/api/v1/session", nil)
	if code != 200 || out["roles"].([]any)[0] != "auditor" {
		t.Fatalf("roles must survive the reset: %d %v", code, out)
	}

	// A second reset revokes the first (now accepted, so nothing pending) and
	// unknown users are refused.
	if _, err := e.App.ResetUser(ctx, "acme", "nobody@acme.test"); !errors.Is(err, app.ErrResetNotAllowed) {
		t.Fatalf("unknown user: %v", err)
	}
	again, err := e.App.ResetUser(ctx, "acme", em)
	if err != nil || again.RevokedInvitation != 0 {
		t.Fatalf("second reset: %+v %v", again, err)
	}
	third, err := e.App.ResetUser(ctx, "acme", em)
	if err != nil || third.RevokedInvitation != 1 {
		t.Fatalf("a new reset must revoke the pending link: %+v %v", third, err)
	}
}
