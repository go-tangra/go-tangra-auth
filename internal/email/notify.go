package email

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-notification/sdk/v4/pkg/notifyclient"
)

// ConnFunc returns the mesh connection to notification. The outbox is built
// before the Freya app, so the connection is asked for on first use.
type ConnFunc func(ctx context.Context) (grpc.ClientConnInterface, error)

// Notifier delivers through notification's Notifier.Send by template key; the
// tenant is the item's tenant and the correlation id is the outbox item id.
type Notifier struct {
	conn   ConnFunc
	mu     sync.Mutex
	client *notifyclient.Client
}

// NewNotifier wires the deliverer; nothing is dialled until the first message.
func NewNotifier(conn ConnFunc) *Notifier { return &Notifier{conn: conn} }

func (n *Notifier) get(ctx context.Context) (*notifyclient.Client, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.client == nil {
		cc, err := n.conn(ctx)
		if err != nil {
			return nil, err
		}
		n.client = notifyclient.New(cc)
	}
	return n.client, nil
}

// Deliver implements Deliverer. notification unreachable, throttling and
// transient relay errors are Retry; a refused key, an unconfigured channel or
// a permanent relay answer is Failed. Reasons come from notification, which
// scrubs secret variables; auth adds none of the values.
func (n *Notifier) Deliver(ctx context.Context, m Message) (Outcome, error) {
	c, err := n.get(ctx)
	if err != nil {
		return Retry, fmt.Errorf("notification unavailable: %w", err)
	}
	res, err := c.SendKey(ctx, m.TenantID, m.Template, m.To, m.Vars, m.ID)
	if err != nil {
		st := status.Convert(err)
		if ctx.Err() != nil || st.Code() == codes.Canceled {
			return Retry, fmt.Errorf("notification: %s", codes.Canceled)
		}
		return Failed, fmt.Errorf("notification refused: %s: %s", st.Code(), st.Message())
	}
	switch {
	case res.Sent:
		return Sent, nil
	case res.Retryable:
		return Retry, errors.New("notification: " + res.Reason)
	default:
		return Failed, errors.New("notification: " + res.Reason)
	}
}
