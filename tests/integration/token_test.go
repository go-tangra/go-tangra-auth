//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
)

func TestTokenLifecycle(t *testing.T) {
	e := Start(t)
	tid, uid := e.Seed("acme", "alice@acme.test", pw, "")
	if code := e.SignIn("acme", "alice@acme.test", pw); code != 200 {
		t.Fatal(code)
	}
	code, out := e.JSON(http.MethodPost, "/api/v1/session/token", nil)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	tok := out["access_token"].(string)
	if !strings.HasPrefix(tok, "eyJ") || out["token_type"] != "Bearer" {
		t.Fatalf("%v", out)
	}
	v := e.Verifier(nil)
	id, err := v.Verify(context.Background(), tok)
	if err != nil || id.UserID != uid || id.TenantID != tid {
		t.Fatalf("%+v %v", id, err)
	}
	// Expiry: a verifier whose clock is 16 minutes ahead refuses the token.
	late := e.Verifier(func() time.Time { return time.Now().Add(16 * time.Minute) })
	if _, err := late.Verify(context.Background(), tok); !errors.Is(err, authclient.ErrUnauthenticated) {
		t.Fatalf("expired token accepted: %v", err)
	}
	// JWKS publishes the active key with its state.
	code, out = e.JSON(http.MethodGet, "/.well-known/jwks.json", nil)
	keys := out["keys"].([]any)
	if code != 200 || len(keys) == 0 || keys[0].(map[string]any)["freya_state"] != "active" {
		t.Fatalf("%d %v", code, out)
	}
	// Sign-out revokes: the verifier sees it within the 5 s poll (here: one sync).
	if code, _ := e.JSON(http.MethodPost, "/api/v1/signout", nil); code != 204 {
		t.Fatal("signout")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_ = v.SyncRevocations(context.Background())
		_, err = v.Verify(context.Background(), tok)
		if errors.Is(err, authclient.ErrRevoked) || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !errors.Is(err, authclient.ErrRevoked) {
		t.Fatalf("revocation not observed within 10 s: %v", err)
	}
	if code, _ := e.JSON(http.MethodGet, "/api/v1/session", nil); code != 401 {
		t.Fatal("session survived sign-out")
	}
}
