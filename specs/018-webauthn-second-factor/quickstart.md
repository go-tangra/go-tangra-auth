# Quickstart: validating security keys (018)

Automated (CI): Go unit tests with a software authenticator (ES256, in
`internal/webauthn/softkey_test.go`), integration tests against
Postgres/Valkey, fuzz targets for the parse wrappers, console vitest with a
stubbed `navigator.credentials`, and a Playwright scenario using the Chrome
DevTools virtual authenticator (`WebAuthn.addVirtualAuthenticator`).

Manual (production, with a YubiKey):

1. Account → Second factors → Add security key → name "YubiKey desk" → touch
   the key. The key is listed; if it was the first factor, ten recovery codes
   are shown once.
2. Sign out, sign in with the password: the second step offers "Use security
   key" → touch → signed in. Audit shows `signin_ok` with `amr pwd,hwk`.
3. Rename the key; add a second key; remove the first after confirming with
   the second key.
4. Sign in with a recovery code while no key is at hand.
5. Admin → Users → the user → Security: two methods shown; Reset second
   factors → the user must set one up again at next sign-in (the platform
   tenant requires it).
6. Negative: open the console by IP address instead of the host name → adding
   a key is refused with the expected address named.
