// Package permref is the grammar of module-scoped permissions (feature 019):
// qualified references "module:resource:action", legacy "resource:action",
// their OpenFGA object ids, the module derived from a SPIFFE identity and the
// role slug grammars (custom, module role definitions, "m.<module>.<slug>").
// It is pure and dependency-free so every layer shares one definition.
package permref

import (
	"errors"
	"regexp"
	"strings"
)

// ErrMalformed is returned for anything outside the grammar.
var ErrMalformed = errors.New("permref: malformed")

var (
	moduleRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	resourceRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	actionRE   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	defSlugRE  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)
	customRE   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	tenantRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ValidModule reports whether s is a module name (the SPIFFE service name).
func ValidModule(s string) bool { return moduleRE.MatchString(s) }

// ValidResource reports whether s is a permission resource.
func ValidResource(s string) bool { return resourceRE.MatchString(s) }

// ValidAction reports whether s is a permission action.
func ValidAction(s string) bool { return actionRE.MatchString(s) }

// ValidRoleDefSlug reports whether s is the slug of a module role definition.
func ValidRoleDefSlug(s string) bool { return defSlugRE.MatchString(s) }

// Ref is a permission. An empty Module is a legacy (pre-019) permission.
type Ref struct{ Module, Resource, Action string }

// IsLegacy reports whether the permission belongs to no module.
func (r Ref) IsLegacy() bool { return r.Module == "" }

// Short renders "resource:action".
func (r Ref) Short() string { return r.Resource + ":" + r.Action }

// String renders "module:resource:action", or "resource:action" when legacy.
func (r Ref) String() string {
	if r.IsLegacy() {
		return r.Short()
	}
	return r.Module + ":" + r.Short()
}

// WithModule returns the same resource and action under module m.
func (r Ref) WithModule(m string) Ref { return Ref{Module: m, Resource: r.Resource, Action: r.Action} }

// Object renders the OpenFGA object id: "permission:<tid>/<module>~<res>~<act>"
// or, legacy, "permission:<tid>/<res>~<act>". '~' is outside every name grammar.
func (r Ref) Object(tid string) string {
	if r.IsLegacy() {
		return "permission:" + tid + "/" + r.Resource + "~" + r.Action
	}
	return "permission:" + tid + "/" + r.Module + "~" + r.Resource + "~" + r.Action
}

func build(module, res, act string) (Ref, error) {
	if (module != "" && !ValidModule(module)) || !ValidResource(res) || !ValidAction(act) {
		return Ref{}, ErrMalformed
	}
	return Ref{Module: module, Resource: res, Action: act}, nil
}

// Parse parses a qualified "module:resource:action".
func Parse(s string) (Ref, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 || parts[0] == "" {
		return Ref{}, ErrMalformed
	}
	return build(parts[0], parts[1], parts[2])
}

// ParseLegacy parses a legacy "resource:action".
func ParseLegacy(s string) (Ref, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return Ref{}, ErrMalformed
	}
	return build("", parts[0], parts[1])
}

// ParseAny parses either form, telling them apart by the number of parts.
func ParseAny(s string) (Ref, error) {
	if strings.Count(s, ":") == 2 {
		return Parse(s)
	}
	return ParseLegacy(s)
}

// Qualify parses a short "resource:action" and places it in module.
func Qualify(module, short string) (Ref, error) {
	r, err := ParseLegacy(short)
	if err != nil || !ValidModule(module) {
		return Ref{}, ErrMalformed
	}
	return r.WithModule(module), nil
}

// ParseObject parses a permission object id back into its tenant and Ref.
func ParseObject(obj string) (string, Ref, error) {
	rest, ok := strings.CutPrefix(obj, "permission:")
	if !ok {
		return "", Ref{}, ErrMalformed
	}
	tid, name, ok := strings.Cut(rest, "/")
	if !ok || !tenantRE.MatchString(tid) {
		return "", Ref{}, ErrMalformed
	}
	parts := strings.Split(name, "~")
	var r Ref
	var err error
	switch len(parts) {
	case 2:
		r, err = build("", parts[0], parts[1])
	case 3:
		if parts[0] == "" {
			return "", Ref{}, ErrMalformed
		}
		r, err = build(parts[0], parts[1], parts[2])
	default:
		return "", Ref{}, ErrMalformed
	}
	if err != nil {
		return "", Ref{}, err
	}
	return tid, r, nil
}

// ModuleFromSPIFFE returns the service name of "spiffe://<trust domain>/svc/<name>".
// Any other path shape, or a name outside the module grammar, is refused.
func ModuleFromSPIFFE(id string) (string, error) {
	rest, ok := strings.CutPrefix(id, "spiffe://")
	if !ok {
		return "", ErrMalformed
	}
	td, path, ok := strings.Cut(rest, "/")
	if !ok || td == "" {
		return "", ErrMalformed
	}
	name, ok := strings.CutPrefix(path, "svc/")
	if !ok || !ValidModule(name) {
		return "", ErrMalformed
	}
	return name, nil
}

// ModuleRoleSlug builds the tenant role slug "m.<module>.<slug>" of a module
// role. Custom slugs cannot contain dots, so the "m." space is reserved.
func ModuleRoleSlug(module, slug string) (string, error) {
	if !ValidModule(module) || !ValidRoleDefSlug(slug) {
		return "", ErrMalformed
	}
	return "m." + module + "." + slug, nil
}

// ParseModuleRoleSlug splits "m.<module>.<slug>".
func ParseModuleRoleSlug(s string) (module, slug string, ok bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] != "m" || !ValidModule(parts[1]) || !ValidRoleDefSlug(parts[2]) {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// ReservedSlugs are the built-in role slugs; custom roles may not use them.
var ReservedSlugs = []string{"owner", "admin", "member", "auditor", "operator"}

// IsReserved reports whether slug names a built-in role.
func IsReserved(slug string) bool {
	for _, s := range ReservedSlugs {
		if s == slug {
			return true
		}
	}
	return false
}

// ParseCustomSlug validates the slug of an administrator-defined role:
// lowercase letters, digits and dashes (no dots), 1–63 characters, not reserved.
func ParseCustomSlug(s string) (string, error) {
	if !customRE.MatchString(s) || IsReserved(s) {
		return "", ErrMalformed
	}
	return s, nil
}
