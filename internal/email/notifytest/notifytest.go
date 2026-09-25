// Package notifytest is an in-process notification Notifier for tests: it
// records every send (key, variables, correlation id) and answers SENT unless
// told otherwise.
package notifytest

import (
	"context"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	notificationv1 "github.com/go-tangra/go-tangra-notification/sdk/v4/api/proto/notification/v1"
)

// Reply decides the answer to a send (nil = SENT).
type Reply func(*notificationv1.SendRequest) (*notificationv1.SendResponse, error)

// Server is a fake Notifier on an in-memory listener.
type Server struct {
	notificationv1.UnimplementedNotifierServer
	lis   *bufconn.Listener
	srv   *grpc.Server
	mu    sync.Mutex
	sends []*notificationv1.SendRequest
	reply Reply
}

// Start serves until Close.
func Start() *Server {
	s := &Server{lis: bufconn.Listen(1 << 20), srv: grpc.NewServer()}
	notificationv1.RegisterNotifierServer(s.srv, s)
	go func() { _ = s.srv.Serve(s.lis) }()
	return s
}

// Dial opens a client connection to the fake (plaintext, in memory).
func (s *Server) Dial() (*grpc.ClientConn, error) {
	return grpc.NewClient("passthrough:///notification", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return s.lis.DialContext(ctx) }))
}

// Close stops the server; later sends fail as Unavailable.
func (s *Server) Close() { s.srv.Stop() }

// SetReply changes the answer for later sends.
func (s *Server) SetReply(r Reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reply = r
}

// Send implements Notifier.Send.
func (s *Server) Send(_ context.Context, in *notificationv1.SendRequest) (*notificationv1.SendResponse, error) {
	s.mu.Lock()
	s.sends = append(s.sends, in)
	r := s.reply
	s.mu.Unlock()
	if r != nil {
		return r(in)
	}
	return &notificationv1.SendResponse{LogId: in.GetCorrelationId(), Status: notificationv1.DeliveryStatus_DELIVERY_STATUS_SENT}, nil
}

// Last is the newest send to a recipient.
func (s *Server) Last(to string) (*notificationv1.SendRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.sends) - 1; i >= 0; i-- {
		if s.sends[i].GetRecipient() == to {
			return s.sends[i], true
		}
	}
	return nil, false
}

// Count is the number of sends to a recipient.
func (s *Server) Count(to string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.sends {
		if r.GetRecipient() == to {
			n++
		}
	}
	return n
}
