package authclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPKeys fetches /.well-known/jwks.json over HTTPS.
type HTTPKeys struct {
	URL    string
	Client *http.Client // nil = a 10 s client with system roots
}

func (h HTTPKeys) Keys(ctx context.Context) (map[string]ed25519.PublicKey, error) {
	if !strings.HasPrefix(h.URL, "https://") {
		return nil, errors.New("authclient: jwks url must be https")
	}
	c := h.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authclient: jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if err != nil {
		return nil, err
	}
	return ParseJWKS(body)
}
