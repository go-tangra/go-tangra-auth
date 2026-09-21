package token

import (
	"testing"
	"time"
)

func TestIssueVerifyEnrollment(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	r, _ := newRing(t, &now)
	iss := NewIssuer(r, "https://auth.example.org")
	iss.now = r.now

	tok, grant, err := iss.IssueEnrollment("t1", []string{"svc/notification"}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if grant.JTI == "" || grant.TenantID != "t1" || grant.SpiffePaths[0] != "svc/notification" {
		t.Fatalf("grant %+v", grant)
	}
	got, err := iss.VerifyEnrollment(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.JTI != grant.JTI || got.TenantID != "t1" || got.SpiffePaths[0] != "svc/notification" {
		t.Fatalf("verified %+v", got)
	}

	// wrong audience: an access token must not verify as an enrollment token.
	access, _, _ := iss.Issue(Request{UserID: "u1", TenantID: "t1", SessionID: "s1", Audience: "app"})
	if _, err := iss.VerifyEnrollment(access); err == nil {
		t.Fatal("access token accepted as enrollment token")
	}

	// expired.
	past := now.Add(-time.Hour)
	iss2 := NewIssuer(r, "https://auth.example.org")
	iss2.now = func() time.Time { return past }
	old, _, _ := iss2.IssueEnrollment("t1", []string{"svc/x"}, time.Minute)
	if _, err := iss.VerifyEnrollment(old); err == nil {
		t.Fatal("expired enrollment token accepted")
	}
}
