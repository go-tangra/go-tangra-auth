package fuzz

import (
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
)

// FuzzOutboxPayload feeds arbitrary JSON to the outbox payload decoder: it
// never panics, anything it accepts names an auth.* template, and an accepted
// payload survives a v2 re-encode unchanged.
func FuzzOutboxPayload(f *testing.F) {
	f.Add(`{"v":2,"template":"auth.invite","vars":{"link":"https://a/?token=x","valid_for":"72 hours"}}`)
	f.Add(`{"subject":"You have been invited","text":"Accept:\n\nhttps://a/?token=x\n"}`)
	f.Add(`{"v":2,"template":"warden.share"}`)
	f.Add(`{"v":3}`)
	f.Add(`{"v":null,"text":null}`)
	f.Add(`[]`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, s string) {
		p, err := email.DecodePayload([]byte(s))
		if err != nil {
			return
		}
		if p.V != email.PayloadVersion || !strings.HasPrefix(p.Template, "auth.") {
			t.Fatalf("accepted %q as %+v", s, p)
		}
		js, err := email.EncodePayload(p)
		if err != nil {
			t.Fatalf("re-encode %+v: %v", p, err)
		}
		q, err := email.DecodePayload(js)
		if err != nil || q.Template != p.Template || len(q.Vars) != len(p.Vars) {
			t.Fatalf("round trip %+v → %+v %v", p, q, err)
		}
		for k, v := range p.Vars {
			if q.Vars[k] != v {
				t.Fatalf("var %q changed", k)
			}
		}
	})
}
