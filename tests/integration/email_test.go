//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	notificationv1 "github.com/go-tangra/go-tangra-notification/sdk/v4/api/proto/notification/v1"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// TestEmailGivenUpOnce (feature 017): a permanent refusal from notification
// retires the outbox row — failed_at and a short reason — and reports it once
// (one email_given_up audit event); later worker passes neither send nor
// report it again. A row queued by auth ≤ 4.1 ({subject,text}) is still
// delivered, as auth.message.
func TestEmailGivenUpOnce(t *testing.T) {
	e := Start(t)
	ctx := context.Background()
	tid, _ := e.Seed("acme", "bounce@acme.test", pw, "")
	e.Notify.SetReply(func(r *notificationv1.SendRequest) (*notificationv1.SendResponse, error) {
		if r.GetRecipient() == "bounce@acme.test" {
			return &notificationv1.SendResponse{LogId: r.GetCorrelationId(), Status: notificationv1.DeliveryStatus_DELIVERY_STATUS_FAILED, Error: "550 no such user"}, nil
		}
		return &notificationv1.SendResponse{LogId: r.GetCorrelationId(), Status: notificationv1.DeliveryStatus_DELIVERY_STATUS_SENT}, nil
	})
	if st, _ := e.JSON(http.MethodPost, "/api/v1/recovery", map[string]string{"tenant": "acme", "email": "bounce@acme.test"}); st != 202 {
		t.Fatal(st)
	}
	r := e.LastSend("bounce@acme.test")
	var failed *time.Time
	var reason *string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_ = e.App.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, "SELECT failed_at, last_error FROM outbox WHERE id = $1", r.GetCorrelationId()).Scan(&failed, &reason)
		})
		if failed != nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if failed == nil || reason == nil || !strings.Contains(*reason, "550") || strings.Contains(*reason, "token=") {
		t.Fatalf("row not retired: failed_at=%v reason=%v", failed, reason)
	}
	if n := e.AuditCount(tid, "email_given_up"); n != 1 {
		t.Fatalf("email_given_up events: %d", n)
	}
	// Two more worker passes (every 5 s): no resend, no second report.
	if _, err := e.App.Outbox.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * time.Second)
	if n := e.Notify.Count("bounce@acme.test"); n != 1 {
		t.Fatalf("retired message sent again: %d", n)
	}
	if n := e.AuditCount(tid, "email_given_up"); n != 1 {
		t.Fatalf("given-up reported again: %d", n)
	}

	// A legacy row sealed with the unchanged AAD is sent as auth.message.
	legacy, err := e.App.Envelope.Encrypt([]byte(`{"subject":"You have been invited","text":"Accept: https://x/?token=LEGACY"}`), []byte("email:old@acme.test"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.App.Store.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error {
		return store.EnqueueOutbox(ctx, tx, store.OutboxItem{ID: store.NewID(), TenantID: tid, Kind: "invite", ToEmail: "old@acme.test", PayloadEnc: legacy})
	}); err != nil {
		t.Fatal(err)
	}
	if mail := e.LastMail("old@acme.test"); mail != "Accept: https://x/?token=LEGACY" {
		t.Fatalf("legacy text %q", mail)
	}
	if r := e.LastSend("old@acme.test"); r.GetTemplateKey() != "auth.message" || r.GetVariables()["subject"] != "You have been invited" || r.GetTenantId() != tid {
		t.Fatalf("legacy send %+v", r)
	}
}
