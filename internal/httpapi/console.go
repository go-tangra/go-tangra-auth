package httpapi

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

// noncePlaceholder in index.html is replaced with the per-request CSP nonce;
// gatewayPlaceholder tells the console whether a platform shell owns "/".
const (
	noncePlaceholder   = "__CSP_NONCE__"
	gatewayPlaceholder = "__GATEWAY__"
)

// consoleHandler serves the built SPA: hashed assets immutable, index.html
// no-store with the CSP nonce injected, unknown paths fall back to index.html.
func consoleHandler(dist fs.FS, gatewayMode bool) http.Handler {
	gatewayFlag := []byte("0")
	if gatewayMode {
		gatewayFlag = []byte("1")
	}
	index, _ := fs.ReadFile(dist, "index.html")
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if p != "" && p != "index.html" {
			if st, err := fs.Stat(dist, p); err == nil && !st.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-cache")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		if len(index) == 0 {
			WriteError(w, http.StatusNotFound, ErrNotFound.Reason)
			return
		}
		// A fresh browser needs the double-submit token before its first
		// state-changing call (sign-in, invitation, recovery).
		if _, err := r.Cookie(edge.CSRFCookie); err != nil {
			edge.IssueCSRFCookie(w)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		// Behind the gateway the CSP (and its nonce) belong to the gateway's
		// edge, relayed in X-CSP-Nonce; only the gateway can reach this server.
		nonce := edge.Nonce(r.Context())
		if nonce == "" && gatewayMode {
			nonce = relayedNonce(r.Header.Get("X-CSP-Nonce"))
		}
		page := bytes.ReplaceAll(index, []byte(noncePlaceholder), []byte(nonce))
		// #nosec G705 -- the only request-derived bytes are the nonce, restricted to base64url characters by relayedNonce.
		_, _ = w.Write(bytes.ReplaceAll(page, []byte(gatewayPlaceholder), gatewayFlag))
	})
}

// relayedNonce returns the gateway-relayed nonce when it is plain base64 /
// base64url text of sane length, and "" otherwise, so a header value can never
// break out of the nonce attribute it is written into.
func relayedNonce(v string) string {
	if len(v) > 128 {
		return ""
	}
	for _, c := range v {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', strings.ContainsRune("+/=_-", c):
		default:
			return ""
		}
	}
	return v
}

// remoteHandler serves the federated remote: mf-manifest.json is never cached,
// hashed assets are immutable, nothing falls back to index.html.
func remoteHandler(dist fs.FS) http.Handler {
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		st, err := fs.Stat(dist, p)
		if p == "" || err != nil || st.IsDir() || p == "index.html" {
			WriteError(w, http.StatusNotFound, ErrNotFound.Reason)
			return
		}
		switch {
		case strings.HasSuffix(p, "mf-manifest.json"):
			w.Header().Set("Cache-Control", "no-store")
		case strings.HasPrefix(p, "assets/"):
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		default:
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
