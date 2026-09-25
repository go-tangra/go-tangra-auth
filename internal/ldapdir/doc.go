// Package ldapdir is the outbound LDAP boundary: dial-time target policy,
// TLS configuration, filter and DN validation, attribute mapping and a small
// Directory/Session interface over go-ldap. It holds no tenant state and never
// touches the database; the directory service is its only caller.
//
// Security notes:
//   - Every dial goes through the policy dialer, whose Control hook checks the
//     resolved IP and port actually being dialled (DNS-rebinding safe). The
//     always-denied set (unspecified, loopback, link-local incl. cloud metadata,
//     multicast and their IPv4-mapped forms) cannot be overridden; other
//     platform ranges are denied by config and only allowed ports are reachable.
//   - Transport is ldaps or mandatory StartTLS with certificate verification
//     against a pinned CA or the system roots. TLS 1.3 is the floor unless a
//     connection opts into TLS 1.2 with approved AEAD/ECDHE suites. There is no
//     skip-verify option, and a failed StartTLS never falls back to plaintext.
//   - User filters are compiled (RFC 4515), size/depth capped, checked for
//     attribute and matching-rule names and re-serialised canonically before being ANDed with
//     the base filter, so input cannot escape the combination. Returned entry
//     DNs are re-checked against the base; aliases are not dereferenced and
//     referrals are not followed.
//   - Only mapped attributes are requested and decoded values are length-capped;
//     over-long values mark the entry invalid instead of being truncated.
//   - Errors form a closed vocabulary. Server diagnostic text is dropped, so a
//     server that echoes the bind DN or password cannot leak it. Bind passwords
//     are passed as []byte, never retained, logged or wrapped into errors.
//
// The package is on the 100 % coverage gate and its parsers are fuzzed.
package ldapdir
