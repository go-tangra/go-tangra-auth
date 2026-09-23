//go:build tools

// Package tools pins github.com/go-ldap/ldap/v3 in go.mod until
// internal/ldapdir imports it (feature 016, research D2). The build tag keeps it
// out of every binary; delete this file once internal/ldapdir/client.go exists.
package tools

import _ "github.com/go-ldap/ldap/v3"
