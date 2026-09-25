package email

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestLogSink(t *testing.T) {
	var buf bytes.Buffer
	l := LogSink{Log: slog.New(slog.NewTextHandler(&buf, nil))}
	out, err := l.Deliver(context.Background(), Message{ID: "1", To: "b@x", Template: TemplateInvite, Vars: map[string]string{"link": "https://auth/accept?token=T"}})
	if err != nil || out != Sent {
		t.Fatal(out, err)
	}
	// Development only: the link is printed so flows complete without a mailbox.
	if !strings.Contains(buf.String(), "token=T") || !strings.Contains(buf.String(), TemplateInvite) {
		t.Fatalf("log sink output %q", buf.String())
	}
}
