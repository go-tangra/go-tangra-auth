// Package authmanifest declares what the authentication module registers with
// the application gateway: its browser API and console prefixes, the API
// permissions of the console and the CASL abilities the shell derives from
// them. It is public so the gateway's contract tests can validate it.
package authmanifest

import (
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/go-freya/freya/services/auth/api/openapi"
	"github.com/go-freya/freya/services/gateway/pkg/gatewayclient"
)

// Module is the registered module name; ConsolePrefix is where the console lives.
const (
	Module        = "auth"
	ConsolePrefix = "/console"
	Version       = "1.2.0"
)

// Permissions the console registers (granted to builtin roles by the service).
var Permissions = []gatewayclient.Permission{
	{Resource: "profile", Action: "read", Description: "See and manage the own account, sessions and second factor"},
	{Resource: "users", Action: "manage", Description: "Invite, deactivate and assign roles to users of the tenant"},
	{Resource: "groups", Action: "manage", Description: "Create groups, manage their members and the roles they grant"},
	{Resource: "roles", Action: "manage", Description: "Create and edit custom roles"},
	{Resource: "policy", Action: "manage", Description: "Edit the tenant sign-in policy"},
	{Resource: "audit", Action: "read", Description: "Read the tenant audit log"},
	{Resource: "clients", Action: "manage", Description: "Register OAuth client applications"},
	{Resource: "directory", Action: "manage", Description: "Connect LDAP directories, search them and import users as inactive"},
	{Resource: "tenants", Action: "operate", Description: "Create, suspend and inspect tenants (platform operators)"},
}

// Grants maps builtin role slugs to the permission references they hold.
var Grants = map[string][]string{
	"owner":    {"profile:read", "users:manage", "groups:manage", "roles:manage", "policy:manage", "audit:read", "clients:manage", "directory:manage"},
	"admin":    {"profile:read", "users:manage", "groups:manage", "roles:manage", "policy:manage", "audit:read", "clients:manage", "directory:manage"},
	"member":   {"profile:read"},
	"auditor":  {"profile:read", "audit:read"},
	"operator": {"profile:read", "users:manage", "groups:manage", "roles:manage", "policy:manage", "audit:read", "clients:manage", "directory:manage", "tenants:operate"},
}

// Manifest builds the gateway manifest from the embedded OpenAPI document.
// Every API route is public at the gateway: the module authenticates browsers
// with its own session cookie (relayed only to this module) and authorizes
// per tenant itself; machine tokens are never required for these routes.
func Manifest() (gatewayclient.Manifest, error) {
	doc, err := openapi3.NewLoader().LoadFromData(openapi.Console)
	if err != nil {
		return gatewayclient.Manifest{}, err
	}
	var routes []gatewayclient.Route
	for p, item := range doc.Paths.Map() {
		for m := range item.Operations() {
			routes = append(routes, gatewayclient.Route{Method: strings.ToUpper(m), Path: p, Public: true})
		}
	}
	routes = append(routes,
		gatewayclient.Route{Method: "GET", Path: ConsolePrefix, Public: true},
		gatewayclient.Route{Method: "GET", Path: ConsolePrefix + "/{path...}", Public: true},
	)
	sort.Slice(routes, func(i, j int) bool { return routes[i].Method+routes[i].Path < routes[j].Method+routes[j].Path })
	return gatewayclient.Manifest{
		Module: Module, DisplayName: "Authentication", Version: Version,
		Prefixes:    []string{"/api/v1", "/authorize", "/.well-known", ConsolePrefix},
		Routes:      routes,
		Permissions: Permissions,
		Abilities: []gatewayclient.Ability{
			{Action: []string{"read", "update"}, Subject: []string{"Profile", "Session"}, Requires: "profile:read"},
			{Action: []string{"manage"}, Subject: []string{"User", "Invitation"}, Requires: "users:manage"},
			{Action: []string{"manage"}, Subject: []string{"Group"}, Requires: "groups:manage"},
			{Action: []string{"manage"}, Subject: []string{"Role"}, Requires: "roles:manage"},
			{Action: []string{"manage"}, Subject: []string{"Policy"}, Requires: "policy:manage"},
			{Action: []string{"read"}, Subject: []string{"AuditEvent"}, Requires: "audit:read"},
			{Action: []string{"manage"}, Subject: []string{"ClientApplication"}, Requires: "clients:manage"},
			{Action: []string{"manage"}, Subject: []string{"DirectoryConnection"}, Requires: "directory:manage"},
			{Action: []string{"manage"}, Subject: []string{"Tenant", "OperatorGrant"}, Requires: "tenants:operate"},
		},
		Exposes: []string{"./routes", "./nav"},
		Nav: []gatewayclient.NavEntry{
			{Title: "Security", Path: ConsolePrefix + "/security", Icon: "mdi-shield-key-outline", Order: 900, Requires: "profile:read"},
			{Title: "Users", Path: ConsolePrefix + "/admin/users", Icon: "mdi-account-multiple-outline", Order: 800, Requires: "users:manage"},
			{Title: "Directories", Path: ConsolePrefix + "/admin/directories", Icon: "mdi-folder-account-outline", Order: 802, Requires: "directory:manage"},
			{Title: "Groups", Path: ConsolePrefix + "/admin/groups", Icon: "mdi-account-group-outline", Order: 805, Requires: "groups:manage"},
			{Title: "Roles", Path: ConsolePrefix + "/admin/roles", Icon: "mdi-account-key-outline", Order: 810, Requires: "roles:manage"},
			{Title: "Policy", Path: ConsolePrefix + "/admin/policy", Icon: "mdi-file-cog-outline", Order: 820, Requires: "policy:manage"},
			{Title: "Audit", Path: ConsolePrefix + "/admin/audit", Icon: "mdi-clipboard-text-clock-outline", Order: 830, Requires: "audit:read"},
			{Title: "Clients", Path: ConsolePrefix + "/admin/clients", Icon: "mdi-application-brackets-outline", Order: 840, Requires: "clients:manage"},
			{Title: "Tenants", Path: ConsolePrefix + "/operator/tenants", Icon: "mdi-domain", Order: 850, Requires: "tenants:operate"},
		},
	}, nil
}

// PermissionRefs lists "resource:action" for every declared permission.
func PermissionRefs() []string {
	out := make([]string, 0, len(Permissions))
	for _, p := range Permissions {
		out = append(out, p.Resource+":"+p.Action)
	}
	return out
}
