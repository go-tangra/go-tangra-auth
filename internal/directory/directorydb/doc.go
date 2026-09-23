// Package directorydb binds the directory package to the database. It is kept
// apart from the domain logic so that logic can be unit-tested without a
// database; these bindings are covered by the tagged integration suite.
//
// Security notes: every call runs in a store.Tx under store.Scope{TenantID}
// so row-level security confines reads and writes to one tenant. The bind
// password column is only ever read and written as sealed ciphertext; this
// package never sees plaintext credentials.
package directorydb
