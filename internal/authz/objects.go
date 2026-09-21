package authz

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-freya/freya/services/auth/internal/tenantctx"
)

var (
	slugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
)

// ErrMalformed is returned for identifiers that do not match the grammar.
var ErrMalformed = errors.New("authz: malformed identifier")

// ParseSlug validates a role slug: lowercase, 1–64 chars, [a-z0-9-], no leading/trailing dash.
func ParseSlug(s string) (string, error) {
	if !slugRE.MatchString(s) {
		return "", ErrMalformed
	}
	return s, nil
}

// PermissionRef is a resource/action pair such as "invoices:read".
type PermissionRef struct{ Resource, Action string }

// ParsePermissionRef parses "resource:action" (each [a-z0-9][a-z0-9_.-]{0,63}).
func ParsePermissionRef(s string) (PermissionRef, error) {
	i := strings.IndexByte(s, ':')
	if i < 0 || strings.Count(s, ":") != 1 {
		return PermissionRef{}, ErrMalformed
	}
	res, act := s[:i], s[i+1:]
	if !nameRE.MatchString(res) || !nameRE.MatchString(act) {
		return PermissionRef{}, ErrMalformed
	}
	return PermissionRef{Resource: res, Action: act}, nil
}

// String renders "resource:action".
func (p PermissionRef) String() string { return p.Resource + ":" + p.Action }

// Object builders. Every object carries its tenant so the model can never be
// asked a question that spans tenants.
func UserObject(uid string) string          { return "user:" + uid }
func TenantObject(tid string) string        { return "tenant:" + tid }
func RoleObject(tid, slug string) string    { return "role:" + tid + "/" + slug }
func RoleAssignees(tid, slug string) string { return RoleObject(tid, slug) + "#assignee" }
func GroupObject(tid, gid string) string    { return "group:" + tid + "/" + gid }
func GroupMembers(tid, gid string) string   { return GroupObject(tid, gid) + "#member" }

// PermissionObject renders "permission:<tenant>/<resource>~<action>": OpenFGA
// object identifiers cannot contain ':' and '~' is outside the name grammar.
func PermissionObject(tid string, p PermissionRef) string {
	return "permission:" + tid + "/" + p.Resource + "~" + p.Action
}

// ObjectTenant extracts and validates the tenant id carried by a tenant, role
// or permission object id.
func ObjectTenant(obj string) (string, error) {
	typ, rest, ok := strings.Cut(obj, ":")
	if !ok {
		return "", ErrMalformed
	}
	var tid string
	switch typ {
	case "tenant":
		tid = rest
	case "role", "permission", "group":
		var ok bool
		tid, _, ok = strings.Cut(rest, "/")
		if !ok {
			return "", ErrMalformed
		}
	default:
		return "", fmt.Errorf("%w: type %q", ErrMalformed, typ)
	}
	if !tenantctx.ValidTenantID(tid) {
		return "", ErrMalformed
	}
	return tid, nil
}
