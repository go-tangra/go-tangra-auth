package email

import (
	"context"
	"log/slog"
)

// LogSink writes messages to the log (development only). Links are logged in
// full on purpose so developers can complete flows without a mailbox.
type LogSink struct{ Log *slog.Logger }

// Deliver implements Deliverer.
func (l LogSink) Deliver(_ context.Context, m Message) (Outcome, error) {
	l.Log.Info("email (dev sink)", "to", m.To, "template", m.Template, "vars", m.Vars)
	return Sent, nil
}
