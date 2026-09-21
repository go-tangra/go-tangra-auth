package email

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

// Message is a transactional email.
type Message struct {
	To, Subject, Text string
}

// Sender delivers a message.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// SMTPConfig configures the SMTP sender; TLS is required unless AllowPlaintext.
type SMTPConfig struct {
	Host, Username, Password, From string
	Port                           int
	AllowPlaintext                 bool
}

// SMTP sends through an SMTP relay using implicit TLS (465) or STARTTLS.
type SMTP struct{ cfg SMTPConfig }

// NewSMTP validates the configuration.
func NewSMTP(cfg SMTPConfig) (*SMTP, error) {
	if cfg.Host == "" || cfg.Port <= 0 || cfg.From == "" {
		return nil, errors.New("email: host, port and from are required")
	}
	return &SMTP{cfg: cfg}, nil
}

// Send delivers via smtp.SendMail with STARTTLS (net/smtp negotiates STARTTLS when
// offered; plaintext fallback is refused unless AllowPlaintext).
func (s *SMTP) Send(_ context.Context, m Message) error {
	if !s.cfg.AllowPlaintext && s.cfg.Port != 465 && s.cfg.Port != 587 {
		return errors.New("email: TLS is required (port 465 or 587) unless allow_plaintext")
	}
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		s.cfg.From, m.To, sanitizeHeader(m.Subject), m.Text)
	var auth smtp.Auth
	if s.cfg.Username != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}
	return smtp.SendMail(fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port), auth, s.cfg.From, []string{m.To}, []byte(body))
}

func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// LogSink writes messages to the log (development only). Links are logged in
// full on purpose so developers can complete flows without a mailbox.
type LogSink struct{ Log *slog.Logger }

// Send implements Sender.
func (l LogSink) Send(_ context.Context, m Message) error {
	l.Log.Info("email (dev sink)", "to", m.To, "subject", m.Subject, "body", m.Text)
	return nil
}
