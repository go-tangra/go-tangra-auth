package contract

import (
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"
	"github.com/go-freya/freya/services/auth/internal/httpapi"
)

// TestOpenAPIDocument proves the contract parses, every operation has an id and
// a refusal schema, and the mounted route table equals the declared one.
func TestOpenAPIDocument(t *testing.T) {
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	for p, item := range doc.Paths.Map() {
		for m, op := range item.Operations() {
			if op.OperationID == "" {
				t.Errorf("%s %s: missing operationId", m, p)
			}
			if op.Responses == nil || op.Responses.Len() == 0 {
				t.Errorf("%s %s: no responses", m, p)
			}
		}
	}
	s, err := httpapi.NewHandler(testrt.New(t, testutil.MustCA("example.org"), "auth"))
	if err != nil {
		t.Fatal(err)
	}
	declared := httpapi.DeclaredRoutes(doc)
	if len(declared) != len(s.Declared()) {
		t.Fatalf("declared %d mounted %d", len(declared), len(s.Declared()))
	}
	set := map[httpapi.Route]bool{}
	for _, r := range declared {
		set[r] = true
	}
	for _, r := range s.Implemented() {
		if !set[r] {
			t.Errorf("implemented but undeclared: %s", r)
		}
	}
	for _, r := range declared {
		if err := s.HandleFunc(r.Method, r.Path, nil); err != nil {
			t.Errorf("declared route cannot be mounted: %s: %v", r, err)
		}
	}
	if got := len(s.Implemented()); got != len(declared) {
		t.Fatalf("mounted %d of %d declared routes", got, len(declared))
	}
}

// directoryRoutes are the connection routes of the LDAP import (feature 016,
// contract A: "Directory connections"); search and import are asserted by
// their own story.
var directoryRoutes = []httpapi.Route{
	{Method: "GET", Path: "/api/v1/admin/directories"},
	{Method: "POST", Path: "/api/v1/admin/directories"},
	{Method: "GET", Path: "/api/v1/admin/directories/{id}"},
	{Method: "PUT", Path: "/api/v1/admin/directories/{id}"},
	{Method: "POST", Path: "/api/v1/admin/directories/{id}/remove"},
	{Method: "POST", Path: "/api/v1/admin/directories/test"},
	{Method: "POST", Path: "/api/v1/admin/directories/{id}/test"},
}

// TestOpenAPIDirectoryConnections pins the connection surface: every route is
// declared, mutations carry the CSRF header, request bodies are closed
// objects, the bind password is write-only on input and never appears in any
// response, and the document version is 1.2.0.
func TestOpenAPIDirectoryConnections(t *testing.T) {
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	if doc.Info == nil || doc.Info.Version != "1.2.0" {
		t.Error("info.version must be 1.2.0")
	}
	for _, r := range directoryRoutes {
		op := operation(doc, r)
		if op == nil {
			t.Errorf("%s: not declared", r)
			continue
		}
		if r.Method != "GET" && !hasCSRF(op) {
			t.Errorf("%s: mutation without the required X-CSRF-Token header", r)
		}
		if strings.Contains(r.Path, "{id}") && !hasUUIDPathID(op) {
			t.Errorf("%s: path parameter id must be a required uuid", r)
		}
		if op.RequestBody != nil && op.RequestBody.Value != nil {
			for ct, mt := range op.RequestBody.Value.Content {
				if mt.Schema == nil || mt.Schema.Value == nil {
					t.Errorf("%s %s: request body without schema", r, ct)
					continue
				}
				assertClosed(t, r.String()+" request", mt.Schema.Value, map[*openapi3.Schema]bool{})
			}
		}
		for code, resp := range op.Responses.Map() {
			if resp.Value == nil {
				continue
			}
			for _, mt := range resp.Value.Content {
				if mt.Schema != nil && mt.Schema.Value != nil {
					assertNoPassword(t, r.String()+" "+code, mt.Schema.Value, map[*openapi3.Schema]bool{})
				}
			}
		}
	}

	// Bodies and responses reference the named schemas.
	for _, r := range []httpapi.Route{directoryRoutes[1], directoryRoutes[3]} {
		if op := operation(doc, r); op != nil {
			if ref := bodyRef(op); ref != "#/components/schemas/DirectoryConnectionInput" {
				t.Errorf("%s: request body must be DirectoryConnectionInput, got %q", r, ref)
			}
		}
	}
	for r, code := range map[httpapi.Route]string{directoryRoutes[1]: "201", directoryRoutes[2]: "200", directoryRoutes[3]: "200"} {
		if op := operation(doc, r); op != nil {
			if ref := responseRef(op, code); ref != "#/components/schemas/DirectoryConnection" {
				t.Errorf("%s %s: response must be DirectoryConnection, got %q", r, code, ref)
			}
		}
	}
	if op := operation(doc, directoryRoutes[0]); op != nil {
		s := responseSchema(op, "200")
		if s == nil || s.Properties["items"] == nil || s.Properties["items"].Value.Items == nil ||
			s.Properties["items"].Value.Items.Ref != "#/components/schemas/DirectoryConnection" {
			t.Errorf("%s: 200 must be {items: DirectoryConnection[]}", directoryRoutes[0])
		}
	}
	for _, r := range directoryRoutes[5:] {
		if op := operation(doc, r); op != nil {
			if ref := responseRef(op, "200"); ref != "#/components/schemas/TestResult" {
				t.Errorf("%s: 200 must be TestResult, got %q", r, ref)
			}
		}
	}
	if op := operation(doc, directoryRoutes[5]); op != nil {
		// Ad-hoc test: the input fields plus connection_id (reuse the stored password).
		if s := bodySchema(op); s == nil || s.Properties["connection_id"] == nil || s.Properties["bind_password"] == nil ||
			!s.Properties["bind_password"].Value.WriteOnly {
			t.Errorf("%s: body must carry the input fields, a write-only bind_password and connection_id", directoryRoutes[5])
		}
	}

	schemas := doc.Components.Schemas
	in := schemaValue(t, schemas, "DirectoryConnectionInput")
	out := schemaValue(t, schemas, "DirectoryConnection")
	tr := schemaValue(t, schemas, "TestResult")
	if in == nil || out == nil || tr == nil {
		return
	}

	// Input: closed, write-only bounded password, the contract's fields.
	assertClosed(t, "DirectoryConnectionInput", in, map[*openapi3.Schema]bool{})
	bp := in.Properties["bind_password"]
	switch {
	case bp == nil || bp.Value == nil:
		t.Error("DirectoryConnectionInput.bind_password missing")
	case !bp.Value.WriteOnly:
		t.Error("DirectoryConnectionInput.bind_password must be writeOnly")
	case bp.Value.MaxLength == nil || *bp.Value.MaxLength != 1024 || bp.Value.MinLength != 1:
		t.Errorf("DirectoryConnectionInput.bind_password must be 1..1024, got %d..%v", bp.Value.MinLength, bp.Value.MaxLength)
	}
	for _, f := range []string{"name", "kind", "url", "tls_mode", "allow_tls12", "ca_pem", "bind_dn", "bind_password", "base_dn", "base_filter", "attributes", "size_limit", "time_limit_seconds"} {
		if in.Properties[f] == nil {
			t.Errorf("DirectoryConnectionInput.%s missing", f)
		}
	}
	for f, max := range map[string]uint64{"name": 80, "url": 512, "ca_pem": 65536, "bind_dn": 1024, "base_dn": 1024, "base_filter": 4096} {
		if p := in.Properties[f]; p != nil && p.Value != nil && (p.Value.MaxLength == nil || *p.Value.MaxLength != max) {
			t.Errorf("DirectoryConnectionInput.%s: maxLength must be %d", f, max)
		}
	}
	assertEnum(t, "DirectoryConnectionInput.kind", in.Properties["kind"], "active_directory", "openldap", "other")
	assertEnum(t, "DirectoryConnectionInput.tls_mode", in.Properties["tls_mode"], "ldaps", "starttls", "plain")

	// Output: exactly the contract's fields (plus ca_pem, which GET /{id}
	// fills) and nothing password-like but the flag.
	assertNoPassword(t, "DirectoryConnection", out, map[*openapi3.Schema]bool{})
	want := []string{"id", "name", "kind", "url", "tls_mode", "allow_tls12", "ca_pem_set", "bind_dn", "bind_password_set",
		"base_dn", "base_filter", "attributes", "size_limit", "time_limit_seconds", "last_test", "created_at", "updated_at"}
	for _, f := range want {
		if out.Properties[f] == nil {
			t.Errorf("DirectoryConnection.%s missing", f)
		}
	}
	for f := range out.Properties {
		if !slices.Contains(want, f) && f != "ca_pem" {
			t.Errorf("DirectoryConnection.%s is not in the contract", f)
		}
	}
	if p := out.Properties["bind_password_set"]; p != nil && (p.Value == nil || !p.Value.Type.Is("boolean")) {
		t.Error("DirectoryConnection.bind_password_set must be a boolean")
	}
	if a := out.Properties["attributes"]; a != nil && a.Value != nil {
		for _, f := range []string{"uid", "email", "display_name", "first_name", "last_name"} {
			if a.Value.Properties[f] == nil {
				t.Errorf("DirectoryConnection.attributes.%s missing", f)
			}
		}
	}

	// TestResult: failing step and closed reason, never server text.
	for _, f := range []string{"ok", "step", "reason", "tls", "duration_ms"} {
		if tr.Properties[f] == nil {
			t.Errorf("TestResult.%s missing", f)
		}
	}
	assertEnum(t, "TestResult.step", tr.Properties["step"], "connect", "tls", "bind", "search_base")
}

func operation(doc *openapi3.T, r httpapi.Route) *openapi3.Operation {
	item := doc.Paths.Value(r.Path)
	if item == nil {
		return nil
	}
	return item.GetOperation(r.Method)
}

func hasCSRF(op *openapi3.Operation) bool {
	for _, p := range op.Parameters {
		if p.Value != nil && p.Value.In == "header" && p.Value.Name == "X-CSRF-Token" && p.Value.Required {
			return true
		}
	}
	return false
}

func hasUUIDPathID(op *openapi3.Operation) bool {
	for _, p := range op.Parameters {
		if v := p.Value; v != nil && v.In == "path" && v.Name == "id" {
			return v.Required && v.Schema != nil && v.Schema.Value != nil && v.Schema.Value.Format == "uuid"
		}
	}
	return false
}

func bodySchemaRef(op *openapi3.Operation) *openapi3.SchemaRef {
	if op.RequestBody == nil || op.RequestBody.Value == nil {
		return nil
	}
	if mt := op.RequestBody.Value.Content.Get("application/json"); mt != nil {
		return mt.Schema
	}
	return nil
}

func bodyRef(op *openapi3.Operation) string {
	if s := bodySchemaRef(op); s != nil {
		return s.Ref
	}
	return ""
}

func bodySchema(op *openapi3.Operation) *openapi3.Schema {
	if s := bodySchemaRef(op); s != nil {
		return s.Value
	}
	return nil
}

func responseSchemaRef(op *openapi3.Operation, code string) *openapi3.SchemaRef {
	resp := op.Responses.Value(code)
	if resp == nil || resp.Value == nil {
		return nil
	}
	if mt := resp.Value.Content.Get("application/json"); mt != nil {
		return mt.Schema
	}
	return nil
}

func responseRef(op *openapi3.Operation, code string) string {
	if s := responseSchemaRef(op, code); s != nil {
		return s.Ref
	}
	return ""
}

func responseSchema(op *openapi3.Operation, code string) *openapi3.Schema {
	if s := responseSchemaRef(op, code); s != nil {
		return s.Value
	}
	return nil
}

func schemaValue(t *testing.T, schemas openapi3.Schemas, name string) *openapi3.Schema {
	t.Helper()
	ref := schemas[name]
	if ref == nil || ref.Value == nil {
		t.Errorf("components.schemas.%s missing", name)
		return nil
	}
	return ref.Value
}

func assertEnum(t *testing.T, where string, ref *openapi3.SchemaRef, want ...string) {
	t.Helper()
	if ref == nil || ref.Value == nil {
		t.Errorf("%s missing", where)
		return
	}
	got := map[string]bool{}
	for _, v := range ref.Value.Enum {
		if s, ok := v.(string); ok {
			got[s] = true
		}
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("%s: enum lacks %q (got %v)", where, w, ref.Value.Enum)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%s: enum must be exactly %v, got %v", where, want, ref.Value.Enum)
	}
}

// assertClosed requires additionalProperties: false on every object schema
// reachable from s (nested objects such as attributes included).
func assertClosed(t *testing.T, where string, s *openapi3.Schema, seen map[*openapi3.Schema]bool) {
	t.Helper()
	if s == nil || seen[s] {
		return
	}
	seen[s] = true
	if s.Type.Is("object") || len(s.Properties) > 0 {
		if s.AdditionalProperties.Has == nil || *s.AdditionalProperties.Has || s.AdditionalProperties.Schema != nil {
			t.Errorf("%s: object schema must set additionalProperties: false", where)
		}
	}
	for name, p := range s.Properties {
		if p != nil {
			assertClosed(t, where+"."+name, p.Value, seen)
		}
	}
	if s.Items != nil {
		assertClosed(t, where+"[]", s.Items.Value, seen)
	}
}

// assertNoPassword refuses any property whose name mentions a password or
// secret anywhere below s, except the bind_password_set flag.
func assertNoPassword(t *testing.T, where string, s *openapi3.Schema, seen map[*openapi3.Schema]bool) {
	t.Helper()
	if s == nil || seen[s] {
		return
	}
	seen[s] = true
	for name, p := range s.Properties {
		l := strings.ToLower(name)
		if name != "bind_password_set" && (strings.Contains(l, "password") || strings.Contains(l, "secret")) {
			t.Errorf("%s: response exposes %q", where, name)
		}
		if p != nil {
			assertNoPassword(t, where+"."+name, p.Value, seen)
		}
	}
	if s.Items != nil {
		assertNoPassword(t, where+"[]", s.Items.Value, seen)
	}
	for _, group := range []openapi3.SchemaRefs{s.AllOf, s.AnyOf, s.OneOf} {
		for _, r := range group {
			if r != nil {
				assertNoPassword(t, where, r.Value, seen)
			}
		}
	}
}

// importRoutes are the search and import routes of the LDAP import (feature
// 016 US2, contract A).
var importRoutes = []httpapi.Route{
	{Method: "POST", Path: "/api/v1/admin/directories/{id}/search"},
	{Method: "POST", Path: "/api/v1/admin/directories/{id}/import"},
}

// TestOpenAPIDirectoryImport pins the search/import surface and the users
// list changes: routes declared with CSRF and a uuid id, closed request
// bodies referencing SearchRequest/ImportRequest, 200 SearchResult /
// ImportResult, the documented refusals, and User.status gaining "imported"
// with the directory origin and pending invitation id.
func TestOpenAPIDirectoryImport(t *testing.T) {
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	wantBody := map[string]string{importRoutes[0].Path: "SearchRequest", importRoutes[1].Path: "ImportRequest"}
	wantResp := map[string]string{importRoutes[0].Path: "SearchResult", importRoutes[1].Path: "ImportResult"}
	wantCodes := map[string][]string{importRoutes[0].Path: {"200", "400", "429", "502", "504"}, importRoutes[1].Path: {"200", "400", "502", "504"}}
	for _, r := range importRoutes {
		op := operation(doc, r)
		if op == nil {
			t.Errorf("%s: not declared", r)
			continue
		}
		if !hasCSRF(op) {
			t.Errorf("%s: mutation without the required X-CSRF-Token header", r)
		}
		if !hasUUIDPathID(op) {
			t.Errorf("%s: path parameter id must be a required uuid", r)
		}
		if ref := bodyRef(op); ref != "#/components/schemas/"+wantBody[r.Path] {
			t.Errorf("%s: request body must be %s, got %q", r, wantBody[r.Path], ref)
		}
		if ref := responseRef(op, "200"); ref != "#/components/schemas/"+wantResp[r.Path] {
			t.Errorf("%s: 200 must be %s, got %q", r, wantResp[r.Path], ref)
		}
		for _, code := range wantCodes[r.Path] {
			if op.Responses.Value(code) == nil {
				t.Errorf("%s: response %s not declared", r, code)
			}
		}
		for code, resp := range op.Responses.Map() {
			if resp.Value == nil {
				continue
			}
			for _, mt := range resp.Value.Content {
				if mt.Schema != nil && mt.Schema.Value != nil {
					assertNoPassword(t, r.String()+" "+code, mt.Schema.Value, map[*openapi3.Schema]bool{})
				}
			}
		}
	}
	// A refused filter carries the parser's position message next to the reason.
	if op := operation(doc, importRoutes[0]); op != nil {
		if s := responseSchema(op, "400"); s == nil || s.Properties["reason"] == nil || s.Properties["message"] == nil {
			t.Errorf("%s: 400 must document reason and message", importRoutes[0])
		}
	}

	schemas := doc.Components.Schemas
	sreq := schemaValue(t, schemas, "SearchRequest")
	sres := schemaValue(t, schemas, "SearchResult")
	ireq := schemaValue(t, schemas, "ImportRequest")
	ires := schemaValue(t, schemas, "ImportResult")
	usr := schemaValue(t, schemas, "User")

	if sreq != nil {
		assertClosed(t, "SearchRequest", sreq, map[*openapi3.Schema]bool{})
		assertProps(t, "SearchRequest", sreq, "filter", "base", "scope")
		if len(sreq.Required) != 0 {
			t.Errorf("SearchRequest: every field is optional, got required %v", sreq.Required)
		}
		assertMaxLength(t, "SearchRequest.filter", sreq.Properties["filter"], 4096)
		assertMaxLength(t, "SearchRequest.base", sreq.Properties["base"], 1024)
		assertEnum(t, "SearchRequest.scope", sreq.Properties["scope"], "one", "sub")
	}
	if sres != nil {
		assertProps(t, "SearchResult", sres, "items", "truncated", "out_of_scope", "effective_filter")
		assertType(t, "SearchResult.truncated", sres.Properties["truncated"], "boolean")
		assertType(t, "SearchResult.out_of_scope", sres.Properties["out_of_scope"], "integer")
		assertType(t, "SearchResult.effective_filter", sres.Properties["effective_filter"], "string")
		if it := arrayItems(sres.Properties["items"]); it == nil {
			t.Error("SearchResult.items must be an array of objects")
		} else {
			assertProps(t, "SearchResult.items[]", it, "uid", "dn", "email", "display_name", "first_name", "last_name", "status", "user_id", "reason")
			assertEnum(t, "SearchResult.items[].status", it.Properties["status"], "new", "existing_user", "imported", "invalid")
			for _, f := range []string{"email", "user_id", "reason"} {
				if p := it.Properties[f]; p != nil && p.Value != nil && !p.Value.Nullable {
					t.Errorf("SearchResult.items[].%s must be nullable", f)
				}
			}
			if p := it.Properties["user_id"]; p != nil && p.Value != nil && p.Value.Format != "uuid" {
				t.Error("SearchResult.items[].user_id must be a uuid")
			}
		}
	}
	if ireq != nil {
		assertClosed(t, "ImportRequest", ireq, map[*openapi3.Schema]bool{})
		assertProps(t, "ImportRequest", ireq, "uids")
		if !slices.Contains(ireq.Required, "uids") {
			t.Error("ImportRequest.uids must be required")
		}
		if u := ireq.Properties["uids"]; u == nil || u.Value == nil || !u.Value.Type.Is("array") {
			t.Error("ImportRequest.uids must be an array")
		} else {
			v := u.Value
			if v.MinItems != 1 || v.MaxItems == nil || *v.MaxItems != 500 || !v.UniqueItems {
				t.Errorf("ImportRequest.uids must be 1..500 unique items, got %d..%v unique=%v", v.MinItems, v.MaxItems, v.UniqueItems)
			}
			assertType(t, "ImportRequest.uids[]", v.Items, "string")
		}
	}
	if ires != nil {
		assertProps(t, "ImportResult", ires, "created", "updated", "skipped", "failed")
		for f, fields := range map[string][]string{"created": {"uid", "user_id"}, "updated": {"uid", "user_id"}, "skipped": {"uid", "reason"}, "failed": {"uid", "reason"}} {
			if it := arrayItems(ires.Properties[f]); it == nil {
				t.Errorf("ImportResult.%s must be an array of objects", f)
			} else {
				assertProps(t, "ImportResult."+f+"[]", it, fields...)
			}
		}
	}
	if usr != nil {
		assertEnum(t, "User.status", usr.Properties["status"], "invited", "active", "deactivated", "locked", "imported")
		if p := usr.Properties["invitation_id"]; p == nil || p.Value == nil || !p.Value.Nullable || p.Value.Format != "uuid" {
			t.Error("User.invitation_id must be a nullable uuid")
		}
		if p := usr.Properties["directory"]; p == nil || p.Value == nil || !p.Value.Nullable {
			t.Error("User.directory must be a nullable object")
		} else {
			assertProps(t, "User.directory", p.Value, "connection_id", "connection_name", "directory_uid", "last_imported_at")
			if c := p.Value.Properties["connection_id"]; c != nil && c.Value != nil && !c.Value.Nullable {
				t.Error("User.directory.connection_id must be nullable (the connection may be deleted)")
			}
		}
	}
}

func assertProps(t *testing.T, where string, s *openapi3.Schema, want ...string) {
	t.Helper()
	for _, f := range want {
		if s.Properties[f] == nil {
			t.Errorf("%s.%s missing", where, f)
		}
	}
	for f := range s.Properties {
		if !slices.Contains(want, f) {
			t.Errorf("%s.%s is not in the contract", where, f)
		}
	}
}

func assertType(t *testing.T, where string, ref *openapi3.SchemaRef, typ string) {
	t.Helper()
	if ref == nil || ref.Value == nil || !ref.Value.Type.Is(typ) {
		t.Errorf("%s must be a %s", where, typ)
	}
}

func assertMaxLength(t *testing.T, where string, ref *openapi3.SchemaRef, n uint64) {
	t.Helper()
	if ref == nil || ref.Value == nil || ref.Value.MaxLength == nil || *ref.Value.MaxLength != n {
		t.Errorf("%s: maxLength must be %d", where, n)
	}
}

func arrayItems(ref *openapi3.SchemaRef) *openapi3.Schema {
	if ref == nil || ref.Value == nil || !ref.Value.Type.Is("array") || ref.Value.Items == nil || ref.Value.Items.Value == nil {
		return nil
	}
	return ref.Value.Items.Value
}
