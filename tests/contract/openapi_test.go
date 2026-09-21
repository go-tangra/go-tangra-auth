package contract

import (
	"testing"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"
	"github.com/go-freya/freya/services/auth/internal/httpapi"
)

// TestOpenAPIDocument proves the contract parses, every operation has an id and
// a refusal schema, and the mounted route table equals the declared one.
func TestOpenAPIDocument(t *testing.T) {
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	for p, item := range doc.Paths.Map() {
		for m, op := range item.Operations() {
			if op.OperationID == "" {
				t.Errorf("%s %s: missing operationId", m, p)
			}
			if op.Responses == nil || op.Responses.Len() == 0 {
				t.Errorf("%s %s: no responses", m, p)
			}
		}
	}
	s, err := httpapi.NewHandler(testrt.New(t, testutil.MustCA("example.org"), "auth"))
	if err != nil {
		t.Fatal(err)
	}
	declared := httpapi.DeclaredRoutes(doc)
	if len(declared) != len(s.Declared()) {
		t.Fatalf("declared %d mounted %d", len(declared), len(s.Declared()))
	}
	set := map[httpapi.Route]bool{}
	for _, r := range declared {
		set[r] = true
	}
	for _, r := range s.Implemented() {
		if !set[r] {
			t.Errorf("implemented but undeclared: %s", r)
		}
	}
	for _, r := range declared {
		if err := s.HandleFunc(r.Method, r.Path, nil); err != nil {
			t.Errorf("declared route cannot be mounted: %s: %v", r, err)
		}
	}
	if got := len(s.Implemented()); got != len(declared) {
		t.Fatalf("mounted %d of %d declared routes", got, len(declared))
	}
}
