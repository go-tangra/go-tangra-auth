# Contract: configuration (018)

```yaml
webauthn:
  enabled: true                 # default true when issuer is https (or http://localhost in dev)
  rp_id: ""                     # default: host of `issuer` (portal.infra.verax.net)
  origins: []                   # default: [origin of `issuer`] (https://portal.infra.verax.net:8443)
  display_name: ""              # default: mfa.issuer ("Tangra")
  user_verification: preferred  # preferred | required
  timeout_seconds: 300          # 30..600
```

Validation at start (refuse to start):
- `rp_id` must equal each origin's host or be a registrable parent of it;
- origins must be `https://` (or `http://localhost[:port]` outside production);
- `user_verification` one of the two values; timeout within bounds.

Warning at start: `webauthn.enabled: false` while users have keys.

No change is needed in go-tangra-docker configs: production derives the
values from `issuer`.
