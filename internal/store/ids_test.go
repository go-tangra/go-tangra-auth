package store

import (
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

func TestNewID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewID()
		if !tenantctx.ValidTenantID(id) || id[14] != '7' || seen[id] {
			t.Fatalf("bad id %q", id)
		}
		seen[id] = true
	}
}
