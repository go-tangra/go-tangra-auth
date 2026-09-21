package grpcapi

import (
	"testing"

	"google.golang.org/grpc"
)

func TestRegisterMountsAllServices(t *testing.T) {
	s := grpc.NewServer()
	Register(s, Handlers{})
	info := s.GetServiceInfo()
	for _, name := range []string{"auth.v1.Keys", "auth.v1.Sessions", "auth.v1.Authorization"} {
		if _, ok := info[name]; !ok {
			t.Errorf("%s not registered", name)
		}
	}
	if len(info["auth.v1.Sessions"].Methods) != 5 || len(info["auth.v1.Authorization"].Methods) != 3 {
		t.Fatalf("methods: %+v", info)
	}
}
