// Package ldapfake is an in-memory implementation of the ldapdir Directory
// interface so the directory, invite and httpapi packages can be tested
// offline, without an LDAP server.
//
// Security notes: this package is for tests only and must never be wired into
// the service binary. It should mirror ldapdir's security contract (bind
// failures as the closed error set, base-scoped results, size-limit
// truncation) so tests against it exercise the same behaviour as production.
// Fixtures must use obviously fake credentials; nothing here is a secret.
package ldapfake
