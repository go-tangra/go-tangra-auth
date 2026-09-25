package email_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	notificationv1 "github.com/go-tangra/go-tangra-notification/sdk/v4/api/proto/notification/v1"

	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
	"github.com/go-tangra/go-tangra-auth/v4/internal/email/notifytest"
)

func msg() email.Message {
	return email.Message{ID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99", TenantID: "t1", To: "a@x.test", Template: email.TemplateInvite,
		Vars: map[string]string{"link": "https://auth/accept?token=T", "valid_for": "72 hours"}}
}

func TestNotifierConnectsLazilyAndPassesKeyVars(t *testing.T) {
	srv := notifytest.Start()
	defer srv.Close()
	var dials atomic.Int32
	n := email.NewNotifier(func(ctx context.Context) (grpc.ClientConnInterface, error) {
		dials.Add(1)
		return srv.Dial()
	})
	if dials.Load() != 0 {
		t.Fatal("no connection before the first delivery")
	}
	for range 2 {
		if out, err := n.Deliver(context.Background(), msg()); out != email.Sent || err != nil {
			t.Fatalf("%v %v", out, err)
		}
	}
	if dials.Load() != 1 {
		t.Fatalf("connection obtained once, got %d", dials.Load())
	}
	r, ok := srv.Last("a@x.test")
	if !ok || r.GetTenantId() != "t1" || r.GetTemplateKey() != email.TemplateInvite || r.GetTemplateId() != "" ||
		r.GetCorrelationId() != msg().ID || r.GetVariables()["link"] != "https://auth/accept?token=T" || r.GetVariables()["valid_for"] != "72 hours" {
		t.Fatalf("request %+v", r)
	}
	if srv.Count("a@x.test") != 2 || srv.Count("b@x.test") != 0 {
		t.Fatal("count")
	}
}

func TestNotifierOutcomes(t *testing.T) {
	srv := notifytest.Start()
	defer srv.Close()
	n := email.NewNotifier(func(context.Context) (grpc.ClientConnInterface, error) { return srv.Dial() })
	cases := []struct {
		name  string
		reply func(*notificationv1.SendRequest) (*notificationv1.SendResponse, error)
		want  email.Outcome
	}{
		{"failed retryable", func(*notificationv1.SendRequest) (*notificationv1.SendResponse, error) {
			return &notificationv1.SendResponse{Status: notificationv1.DeliveryStatus_DELIVERY_STATUS_FAILED, Retryable: true, Error: "421 try later"}, nil
		}, email.Retry},
		{"failed permanent", func(*notificationv1.SendRequest) (*notificationv1.SendResponse, error) {
			return &notificationv1.SendResponse{Status: notificationv1.DeliveryStatus_DELIVERY_STATUS_FAILED, Error: "550 no such user"}, nil
		}, email.Failed},
		{"throttled", func(*notificationv1.SendRequest) (*notificationv1.SendResponse, error) {
			return nil, status.Error(codes.ResourceExhausted, "slow down")
		}, email.Retry},
		{"unknown key", func(*notificationv1.SendRequest) (*notificationv1.SendResponse, error) {
			return nil, status.Error(codes.NotFound, "template_not_found")
		}, email.Failed},
		{"not configured", func(*notificationv1.SendRequest) (*notificationv1.SendResponse, error) {
			return nil, status.Error(codes.FailedPrecondition, "email_not_configured")
		}, email.Failed},
	}
	for _, tc := range cases {
		srv.SetReply(tc.reply)
		out, err := n.Deliver(context.Background(), msg())
		if out != tc.want || err == nil {
			t.Fatalf("%s: %v %v", tc.name, out, err)
		}
		if strings.Contains(err.Error(), "token=T") {
			t.Fatalf("%s: the reason must not carry the link: %v", tc.name, err)
		}
	}
	// A cancelled caller is not a verdict on the message.
	srv.SetReply(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err := n.Deliver(ctx, msg()); out != email.Retry || err == nil {
		t.Fatalf("cancelled: %v %v", out, err)
	}
}

func TestNotifierDown(t *testing.T) {
	// No connection yet (the app is not running or discovery failed): retry,
	// and ask again next time.
	calls := 0
	n := email.NewNotifier(func(context.Context) (grpc.ClientConnInterface, error) {
		calls++
		return nil, errors.New("notification not registered")
	})
	for range 2 {
		if out, err := n.Deliver(context.Background(), msg()); out != email.Retry || err == nil {
			t.Fatalf("%v %v", out, err)
		}
	}
	if calls != 2 {
		t.Fatalf("a failed connection is not cached: %d", calls)
	}
	// Notification stopped after the connection was made: retry.
	srv := notifytest.Start()
	n = email.NewNotifier(func(context.Context) (grpc.ClientConnInterface, error) { return srv.Dial() })
	if out, _ := n.Deliver(context.Background(), msg()); out != email.Sent {
		t.Fatal("first send")
	}
	srv.Close()
	if out, err := n.Deliver(context.Background(), msg()); out != email.Retry || err == nil {
		t.Fatalf("down: %v %v", out, err)
	}
}
