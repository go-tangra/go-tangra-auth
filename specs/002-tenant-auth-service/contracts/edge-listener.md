# Contract: `transport/edge` (framework addition)

Browser-facing listener for Freya services. Complements — never replaces — the mTLS
service listeners.

```go
package edge

type Config struct {
    Addr            string        // default ":8443"
    CertFile, KeyFile string      // PEM, hot-reloaded on change (ACME later)
    AllowedOrigins  []string      // console origin(s) for CSRF Origin checks
    RateLimit       RateLimit     // per-IP token bucket: default 20 req/s burst 40; per-route overrides
    TrustedProxies  []string      // CIDRs allowed to set X-Forwarded-For (default: none)
}

func NewServer(rt transport.Runtime, cfg Config, opts ...ServerOption) (*Server, error)
func (s *Server) Handle / HandleFunc / Route / Use / Endpoint / Start / Stop
```

Guarantees:

- TLS 1.3 only, server-authenticated, `NextProtos ["h2","http/1.1"]`; no plaintext
  option exists; a self-signed dev certificate is generated only when
  `env != production` and logged as `insecure_mode_enabled reason=local_dev`.
- Chain: recover → correlation → tracing → instrumentation → rate limit → security
  headers → CSRF (state-changing methods) → body limit → application handler.
  There is **no** authn/authz peer stage; the application authenticates end users.
- Security headers on every response: `Strict-Transport-Security`,
  `Content-Security-Policy` (default `default-src 'self'; frame-ancestors 'none';
  base-uri 'none'; object-src 'none'` + per-app additions with nonces),
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy` (deny camera/microphone/geolocation), `Cache-Control: no-store`
  for API routes.
- CSRF: double-submit (`__Host-csrf` cookie ↔ `X-CSRF-Token`) plus `Origin` /
  `Sec-Fetch-Site` validation for `POST/PUT/PATCH/DELETE`.
- Limits: Freya `config.Limits` apply (body 1 MiB, headers 8 KiB, timeouts);
  violations and rate-limit rejections are audited as `limit_exceeded`.
- Error encoder: `{"reason": ...}` only.
- Contract tests: no plaintext constructor (reflection walk extended to `transport/edge`);
  header suite; CSRF matrix (missing cookie, missing header, mismatch, bad Origin);
  rate-limit burst; TLS 1.2 refused.
