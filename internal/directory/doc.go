// Package directory is the domain service for LDAP directory connections and
// importing directory people as "imported" users: connection CRUD, test,
// search preview and import. It talks to directories only through ldapdir and
// persists through a Store interface (directorydb in production, memstore in
// tests).
//
// Security notes:
//   - The bind password is sealed with crypto.Envelope using associated data
//     "ldap-bind:<tenant_id>:<connection_id>", so a ciphertext cannot be moved
//     to another tenant or connection. It is decrypted only immediately before
//     Bind, held in a []byte that is zeroed afterwards, and never returned,
//     logged, audited or wrapped into an error. Responses expose only
//     bind_password_set; an empty password (anonymous bind) is refused.
//   - Plaintext transport is refused unless the deployment is non-production
//     and directory.allow_plaintext is set.
//   - Import re-fetches each selected entry from the directory by its unique id
//     under the base DN and base filter, so a client cannot forge names or
//     e-mails. Imported users have no password or MFA, are never sent e-mail by
//     import, and cannot sign in until activated through an invitation.
//   - Every operation is tenant scoped; test and search are rate limited per
//     tenant and report only coarse outcomes to limit probe oracles.
package directory
