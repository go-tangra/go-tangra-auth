package app

import (
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
)

// The break-glass messages name notification templates (feature 017): an
// admin reset is auth.account_reset, the first operator's invitation is
// auth.invite; both links are valid for seven days.
func TestBreakGlassPayloads(t *testing.T) {
	p := resetPayload("https://auth.example.org/console/invite/accept?token=T")
	if p.Template != email.TemplateAccountReset || p.Link() != "https://auth.example.org/console/invite/accept?token=T" || p.Vars["valid_for"] != "7 days" || len(p.Vars) != 2 {
		t.Fatalf("reset %+v", p)
	}
	p = operatorInvitePayload("https://auth.example.org/console/invite/accept?token=T", "Platform")
	if p.Template != email.TemplateInvite || p.Link() == "" || p.Vars["valid_for"] != "7 days" || p.Vars["tenant"] != "Platform" {
		t.Fatalf("operator invite %+v", p)
	}
}

// A retired message is reported as one valid email_given_up audit event that
// names the outbox row, never the recipient or the link.
func TestEmailGivenUpEvent(t *testing.T) {
	e := emailGivenUpEvent(email.GiveUp{ID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99", TenantID: PlatformTenantID, Kind: "invite", Attempts: 8, Reason: "gave up after 8 attempts: Unavailable"})
	if err := audit.Validate(e); err != nil {
		t.Fatal(err)
	}
	if e.Type != audit.EmailGivenUp || e.Outcome != "failed" || e.ActorKind != "system" || e.SubjectKind != "email" || e.SubjectID != "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99" ||
		e.Details["kind"] != "invite" || e.Details["attempts"] != 8 || e.Details["error"] != "gave up after 8 attempts: Unavailable" {
		t.Fatalf("event %+v", e)
	}
}
