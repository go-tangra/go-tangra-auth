# Gateway & shell contract changes (feature 004)

Small, additive changes to feature 003 surfaces.

## `/gateway/v1/me` (identity endpoint)

Response gains two fields, both sourced from `SessionIdentity`
(session callers) or left empty (bearer callers, whose tokens carry no profile):

```json
{ "user_id": "...", "tenant_id": "...", "roles": ["member", "auditor"],
  "display_name": "Dana Kovač", "avatar_url": "/api/v1/users/<uid>/avatar/<sha256>",
  "operator": false, "source": "session" }
```

`roles` are now the user's **effective** roles. `avatar_url` is
gateway-relative and resolves through the auth module's relayed routes with
the platform session cookie; modules embed it directly in `<img>`.

## Identity refresh relay

The dispatcher already invalidates the cached identity of a cookie when the
auth module answers `POST /api/v1/signout` with success. It now also does so
when any response **from the auth module** carries
`X-Freya-Identity-Refresh: 1`. The header is removed before the response
reaches the browser, and is dropped from inbound requests (it is never trusted
from clients). No other module can trigger it (the check is keyed on the
module that owns the route, not on the header alone).

## Shell header

`stores/session.ts` stores `display_name` and `avatar_url` from `/me`;
`layouts/Default.vue` renders an avatar (`v-avatar` with the image, falling
back to initials) and the display name next to the sign-out button
(`data-test="me-name"`, `data-test="me-avatar"`). The shell listens for the
DOM event `freya:session-changed` (dispatched by the auth remote after a
profile or avatar save) and refetches `/me`.

## Manifest (auth module)

- New permission `groups:manage` (owner, admin, operator).
- New ability `manage Group` requiring `groups:manage`.
- New nav entry "Groups" → `/console/admin/groups`, requires `groups:manage`.
- Route `PUT /api/v1/me/avatar` registered with `max_body_bytes: 2162688`.
- All new `/api/v1/...` routes are public at the gateway like the rest of the
  console API (the module authenticates with its own session cookie).
