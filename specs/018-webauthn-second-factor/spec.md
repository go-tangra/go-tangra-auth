# Feature Specification: Security Keys (WebAuthn) as a Second Factor

**Feature Branch**: `018-webauthn-second-factor`

**Created**: 2026-09-26

**Status**: Draft

**Input**: User description: "v3 have a option for webauthn so users with yubikey can use them as second factor. Add same functionality to v4"

## Context

The v3 platform let users register hardware security keys (YubiKey and other
FIDO2/WebAuthn authenticators) and use them instead of a one-time code at
sign-in. v4 auth supports only authenticator-app codes (TOTP) and recovery
codes as a second factor. People who used security keys in v3 lose that on
v4. This feature brings security keys to v4 as a second factor, alongside the
existing authenticator app, without the v3 gaps (no re-confirmation to remove
a key, no attempt limits, recovery codes missing when a key was the first
factor, key names not shown, cloned-key warnings ignored).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Register a security key (Priority: P1)

A signed-in user opens their account security settings, chooses "Add security
key", gives it a name ("YubiKey 5C – desk"), and touches the key when the
browser asks. The key appears in their list of second factors. If this is
their first second factor, they receive recovery codes to store safely.

**Why this priority**: Without registration nothing else is possible; it is
the entry point of the feature.

**Independent Test**: With a software authenticator in a test browser, a user
registers a key, sees it listed with its name and date, and (first factor
only) is shown recovery codes once.

**Acceptance Scenarios**:

1. **Given** a signed-in user without any second factor, **When** they add a
   security key and complete the browser prompt, **Then** the key is listed,
   their account counts as protected by a second factor, and ten recovery
   codes are shown once.
2. **Given** a user who already uses an authenticator app, **When** they add a
   security key, **Then** both methods are listed and no new recovery codes
   are issued.
3. **Given** a user adding a key, **When** they cancel the browser prompt or
   the prompt times out, **Then** nothing is stored and a clear message is
   shown.
4. **Given** a key already registered to the user, **When** they try to
   register the same key again, **Then** it is refused as already registered.
5. **Given** a user with 10 registered keys, **When** they try to add
   another, **Then** it is refused with the limit named.

---

### User Story 2 - Sign in with a security key (Priority: P1)

A user with a registered key signs in with their password; the second step
offers "Use security key" (and "Use authenticator app" / "Use a recovery code"
where applicable). They touch the key and are signed in.

**Why this priority**: This is the value of the feature: the key replaces the
typed code at every sign-in.

**Independent Test**: A user with a registered key signs in with password
plus key and gets a session whose authentication methods record a hardware
key.

**Acceptance Scenarios**:

1. **Given** a user with a registered key, **When** they complete the
   password step, **Then** the second step offers the security key and, if
   set up, the authenticator app and recovery codes.
2. **Given** the second step, **When** the user touches a registered key,
   **Then** they are signed in and the session and audit record that a
   hardware key was used.
3. **Given** the second step, **When** the user presents an unregistered key
   or the assertion is invalid, **Then** sign-in fails, the failure counts
   toward the account lockout exactly like a wrong code, and the audit
   records the refusal.
4. **Given** a key whose signature counter did not increase as required
   (possible clone), **When** it is used, **Then** sign-in is refused, the key
   is flagged, and the audit records a possible cloned authenticator.
5. **Given** a user who only has security keys, **When** their key is not at
   hand, **Then** they can sign in with a recovery code.

---

### User Story 3 - Manage security keys (Priority: P2)

A user sees their keys with name, when each was added and last used, renames
a key, and removes a lost key. Removing requires confirming with a current
second factor (a key, an authenticator code or a recovery code). The last
second factor cannot be removed while the tenant requires two-step sign-in.

**Why this priority**: Keys get lost and replaced; without management a lost
key would need an administrator.

**Independent Test**: A user with two keys renames one, removes the other
after confirming with the remaining key, and the list reflects both changes.

**Acceptance Scenarios**:

1. **Given** a user's key list, **When** they rename a key, **Then** the new
   name is shown.
2. **Given** a user with two second factors, **When** they remove a key and
   confirm with a current factor, **Then** the key no longer works and the
   removal is audited.
3. **Given** a tenant that requires two-step sign-in and a user whose only
   factor is one key, **When** they try to remove it, **Then** it is refused
   until another factor is added.
4. **Given** a tenant that does not require two-step sign-in, **When** a user
   removes their last factor after confirming it, **Then** their account no
   longer asks for a second step and unused recovery codes are invalidated.

---

### User Story 4 - Administrators help a user who lost every factor (Priority: P3)

An administrator can see which second-factor methods a user has (not the key
material) and reset a user's second factors so the user sets them up again
at next sign-in.

**Why this priority**: The break-glass command already covers operators; an
in-console reset reduces the need for host access but is not required to
use keys.

**Independent Test**: An administrator views a user's methods (e.g.
"Security keys: 2, Authenticator app: yes"), resets them, and the user is
asked to set up a second factor at next sign-in.

**Acceptance Scenarios**:

1. **Given** an administrator on a user's page, **When** they look at the
   security section, **Then** they see the number of keys, their names and
   last use, and whether an authenticator app is set — never secrets.
2. **Given** an administrator, **When** they reset a user's second factors
   and confirm, **Then** all keys, the authenticator app and recovery codes
   of that user are removed, the user's sessions are ended, and the action is
   audited with the administrator as actor.
3. **Given** an administrator without the permission to manage users,
   **When** they try to reset, **Then** it is refused.

---

### Edge Cases

- The browser or device does not support security keys: the option is hidden
  or explained, and other methods remain available.
- The platform is reached under a different host name than configured (e.g.
  an IP address): key registration and sign-in are refused with a message
  naming the expected address, because keys are bound to it.
- The platform's public address changes (new domain): existing keys stop
  working; the operator guide explains that users must re-register keys and
  can meanwhile use the authenticator app or recovery codes.
- A second-step attempt started in one tab is completed in another: the
  pending sign-in expires after five minutes or after one successful use.
- Many wrong attempts: security-key failures and code failures share one
  lockout counter per account.
- A key that asks for its PIN (user verification) and one that does not both
  work; the platform does not require the PIN unless configured to.
- Two users register the same physical key: allowed (keys create separate
  credentials per account).
- A user is deactivated or deleted: their keys stop working and are removed
  with the account.

## Requirements *(mandatory)*

### Functional Requirements

**Registration**

- **FR-001**: Signed-in users MUST be able to register a security key as a
  second factor, giving it a name (1–64 characters, unique per user).
- **FR-002**: A user MUST be able to hold up to 10 security keys; the same
  credential cannot be registered twice.
- **FR-003**: Registering the first second factor of any kind MUST issue ten
  single-use recovery codes, shown once; adding further factors MUST NOT
  replace existing codes.
- **FR-004**: A registration attempt MUST expire after five minutes and be
  usable once.

**Sign-in**

- **FR-005**: After a correct password, a user with any second factor MUST
  be asked for one; the second step MUST offer every method the user has:
  security key, authenticator app, recovery code.
- **FR-006**: A valid security key assertion from one of the user's keys
  MUST complete the sign-in; the session and the sign-in audit MUST record a
  hardware key as the authentication method.
- **FR-007**: Failed or invalid security key attempts MUST count toward the
  same per-account lockout and attempt limits as wrong codes.
- **FR-008**: A key whose signature counter indicates a possible clone MUST
  be refused and flagged; the event MUST be audited.
- **FR-009**: Each key MUST record when it was last used successfully.
- **FR-010**: Keys MUST only work for the platform's configured public
  address (relying party); requests from other origins MUST be refused.

**Management**

- **FR-011**: Users MUST be able to list (name, added, last used, flagged),
  rename and remove their keys.
- **FR-012**: Removing a key MUST require confirming with any current second
  factor of the user (a key, an authenticator code or a recovery code).
- **FR-013**: Removing the last second factor MUST be refused while the
  tenant requires two-step sign-in; otherwise it MUST also invalidate unused
  recovery codes.
- **FR-014**: The account security page MUST show authenticator app and
  security keys together as "second factors".

**Administration**

- **FR-015**: Administrators with user-management permission MUST be able to
  see a user's second-factor methods (counts, key names, last use) without
  any key material.
- **FR-016**: Administrators with user-management permission MUST be able to
  reset a user's second factors (keys, authenticator app, recovery codes),
  which also ends the user's sessions.
- **FR-017**: The tenant policy "require two-step sign-in" MUST be satisfied
  by either method.

**Configuration & deployment**

- **FR-018**: The relying-party identity (domain) and allowed origin MUST
  default from the platform's public address and MAY be overridden in
  configuration; the display name defaults to "Tangra".
- **FR-019**: The production guide MUST explain that keys are bound to the
  public host name and what happens when it changes.

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**: public browser ingress through the gateway
  (sign-in, account and admin endpoints); authenticator responses parsed by
  the server.
- **Data classification**: credential public keys and identifiers
  (authentication data, not secret but integrity-critical); recovery codes
  (secret, stored hashed); key names and usage times (account metadata).
- **Authentication/Authorization**: registration and management require an
  authenticated session of the user; the second step requires a pending
  sign-in challenge from a correct password; admin views/reset require the
  user-management permission.
- **Threat scenarios**: phishing (credentials bound to origin and relying
  party); replayed assertions (single-use challenges, counter check); cloned
  authenticators (counter regression → refuse + flag); brute force on the
  second step (shared lockout and rate limits); malformed or oversized
  authenticator data (bounded parsing); key registered to the wrong account
  (challenge bound to the signed-in user); removal by someone with a hijacked
  session (re-confirmation with a factor); enumeration of users' factors
  (methods only revealed after a correct password).
- **SR-001**: Challenges MUST be random, single-use, bound to the user and
  the ceremony type, and expire after five minutes.
- **SR-002**: Only assertions for the configured relying party and origin
  MUST be accepted; attestation is not required (privacy), but user presence
  MUST be verified.
- **SR-003**: Parsing of authenticator responses MUST be size-bounded and
  covered by fuzz tests.
- **SR-004**: Security-key failures MUST share the lockout counter and audit
  vocabulary with other second-factor failures.
- **SR-005**: Removing a factor or resetting a user's factors MUST be audited
  with actor, target and method (never key material).

### Key Entities *(include if feature involves data)*

- **Security Key (credential)**: belongs to one user in one tenant; credential
  identifier, public key, signature counter, authenticator model identifier
  (AAGUID), transports, user-given name, created, last used, flagged as
  possibly cloned.
- **Second-factor state of a user**: which methods are set up (authenticator
  app, keys), recovery codes, whether the account asks for a second step.
- **Pending ceremony**: short-lived registration or sign-in challenge bound
  to a user.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A user can register a security key in under one minute from the
  account page.
- **SC-002**: Signing in with password plus security key takes no more steps
  than password plus authenticator code (one touch instead of typing six
  digits).
- **SC-003**: 100 % of second-step failures, whether code or key, count
  toward the same lockout; automated tests prove the shared limit.
- **SC-004**: A cloned-key signal is refused and audited in 100 % of tested
  cases.
- **SC-005**: Users who used YubiKeys in v3 can register the same key in v4
  and use it the same day without administrator help.

## Assumptions

- Security keys are a second factor only; passwordless sign-in (passkeys) is
  out of scope.
- v3 key registrations are not migrated: they are bound to v3's
  relying-party settings and user handles; users register their keys again
  in v4.
- Attestation is not requested ("none"); any standards-compliant key works.
- User verification (key PIN/biometric) is "preferred" by default and may be
  set to "required" in configuration.
- The relying party is the host name of the public address (e.g.
  `portal.infra.verax.net`); the origin includes the port when not 443.
- Recovery codes stay the shared recovery method for both factor kinds.
- The existing break-glass `reset-user` command keeps working and also
  removes keys.
