package authz

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
)

// SDKConfig connects to an OpenFGA server. TLS is required unless AllowPlaintext.
type SDKConfig struct {
	URL            string
	PresharedKey   string
	StoreID        string // empty = look up / create by StoreName
	StoreName      string
	AllowPlaintext bool
}

// SDKBackend is the OpenFGA-backed Backend.
type SDKBackend struct {
	c    *client.OpenFgaClient
	name string
}

// NewSDKBackend builds the client. Model and store ids are set by Bootstrap.
func NewSDKBackend(cfg SDKConfig) (*SDKBackend, error) {
	if cfg.URL == "" {
		return nil, errors.New("authz: openfga url required")
	}
	if !cfg.AllowPlaintext && !strings.HasPrefix(cfg.URL, "https://") {
		return nil, errors.New("authz: openfga url must use https unless allow_plaintext")
	}
	if cfg.StoreName == "" {
		cfg.StoreName = "auth"
	}
	cc := &client.ClientConfiguration{ApiUrl: cfg.URL, StoreId: cfg.StoreID}
	if cfg.PresharedKey != "" {
		cc.Credentials = &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: cfg.PresharedKey}}
	}
	c, err := client.NewSdkClient(cc)
	if err != nil {
		return nil, fmt.Errorf("authz: openfga client: %w", err)
	}
	return &SDKBackend{c: c, name: cfg.StoreName}, nil
}

func (b *SDKBackend) Check(ctx context.Context, t Tuple) (bool, error) {
	resp, err := b.c.Check(ctx).Body(client.ClientCheckRequest{User: t.User, Relation: t.Relation, Object: t.Object}).Execute()
	if err != nil {
		return false, fmt.Errorf("authz: check: %w", err)
	}
	return resp.GetAllowed(), nil
}

func (b *SDKBackend) BatchCheck(ctx context.Context, ts []Tuple) ([]bool, error) {
	if len(ts) == 0 {
		return nil, nil
	}
	items := make([]client.ClientBatchCheckItem, len(ts))
	for i, t := range ts {
		items[i] = client.ClientBatchCheckItem{User: t.User, Relation: t.Relation, Object: t.Object, CorrelationId: strconv.Itoa(i)}
	}
	resp, err := b.c.BatchCheck(ctx).Body(client.ClientBatchCheckRequest{Checks: items}).Execute()
	if err != nil {
		return nil, fmt.Errorf("authz: batch check: %w", err)
	}
	out := make([]bool, len(ts))
	for id, r := range resp.GetResult() {
		i, err := strconv.Atoi(id)
		if err != nil || i < 0 || i >= len(out) {
			continue
		}
		out[i] = r.GetAllowed()
	}
	return out, nil
}

// MaxTuplesPerWrite is OpenFGA's default limit of tuples in one Write call.
const MaxTuplesPerWrite = 100

// writeOptions makes writes idempotent (feature 019, OpenFGA >= 1.10): a
// duplicate add or a missing delete succeeds, so a registration or a mirror
// repair that repeats a write after a partial failure converges.
var writeOptions = client.ClientWriteOptions{Conflict: client.ClientWriteConflictOptions{
	OnDuplicateWrites: client.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_IGNORE,
	OnMissingDeletes:  client.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_IGNORE,
}}

// writeChunks splits adds and removes into requests of at most
// MaxTuplesPerWrite tuples; each request is atomic, the sequence is not.
func writeChunks(adds, removes []Tuple) []client.ClientWriteRequest {
	var out []client.ClientWriteRequest
	cur := client.ClientWriteRequest{}
	n := 0
	flush := func() {
		if n > 0 {
			out = append(out, cur)
			cur, n = client.ClientWriteRequest{}, 0
		}
	}
	for _, t := range adds {
		if n == MaxTuplesPerWrite {
			flush()
		}
		cur.Writes = append(cur.Writes, client.ClientTupleKey{User: t.User, Relation: t.Relation, Object: t.Object})
		n++
	}
	for _, t := range removes {
		if n == MaxTuplesPerWrite {
			flush()
		}
		cur.Deletes = append(cur.Deletes, client.ClientTupleKeyWithoutCondition{User: t.User, Relation: t.Relation, Object: t.Object})
		n++
	}
	flush()
	return out
}

func (b *SDKBackend) Write(ctx context.Context, adds, removes []Tuple) error {
	for _, req := range writeChunks(adds, removes) {
		if _, err := b.c.Write(ctx).Body(req).Options(writeOptions).Execute(); err != nil {
			return fmt.Errorf("authz: write: %w", err)
		}
	}
	return nil
}

func (b *SDKBackend) EnsureStore(ctx context.Context, name string) (string, error) {
	if id, err := b.c.GetStoreId(); err == nil && id != "" {
		return id, nil
	}
	list, err := b.c.ListStores(ctx).Options(client.ClientListStoresOptions{Name: &name}).Execute()
	if err != nil {
		return "", fmt.Errorf("authz: list stores: %w", err)
	}
	for _, s := range list.GetStores() {
		if s.GetName() == name {
			return s.GetId(), b.c.SetStoreId(s.GetId())
		}
	}
	created, err := b.c.CreateStore(ctx).Body(client.ClientCreateStoreRequest{Name: name}).Execute()
	if err != nil {
		return "", fmt.Errorf("authz: create store: %w", err)
	}
	return created.GetId(), b.c.SetStoreId(created.GetId())
}

func (b *SDKBackend) EnsureModel(ctx context.Context) (string, error) {
	want := Model()
	if latest, err := b.c.ReadLatestAuthorizationModel(ctx).Execute(); err == nil {
		if m, ok := latest.GetAuthorizationModelOk(); ok && SameModel(m, want) {
			return m.GetId(), b.c.SetAuthorizationModelId(m.GetId())
		}
	}
	resp, err := b.c.WriteAuthorizationModel(ctx).Body(want).Execute()
	if err != nil {
		return "", fmt.Errorf("authz: write model: %w", err)
	}
	return resp.GetAuthorizationModelId(), b.c.SetAuthorizationModelId(resp.GetAuthorizationModelId())
}

// SameModel compares type names and relation names (the model has no
// conditions; a structural change always renames or adds a relation).
func SameModel(have *openfga.AuthorizationModel, want openfga.WriteAuthorizationModelRequest) bool {
	if have.GetSchemaVersion() != want.SchemaVersion || len(have.GetTypeDefinitions()) != len(want.TypeDefinitions) {
		return false
	}
	rel := func(td openfga.TypeDefinition) string {
		var names []string
		if td.Relations != nil {
			for k := range *td.Relations {
				names = append(names, k)
			}
		}
		sortStrings(names)
		return td.Type + ":" + strings.Join(names, ",")
	}
	var a, b []string
	for _, td := range have.GetTypeDefinitions() {
		a = append(a, rel(td))
	}
	for _, td := range want.TypeDefinitions {
		b = append(b, rel(td))
	}
	sortStrings(a)
	sortStrings(b)
	return strings.Join(a, ";") == strings.Join(b, ";")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Model is the Go rendering of model.fga (schema 1.1).
func Model() openfga.WriteAuthorizationModelRequest {
	this := func() *map[string]interface{} { m := map[string]interface{}{}; return &m }
	computed := func(rel string) openfga.Userset {
		return openfga.Userset{ComputedUserset: &openfga.ObjectRelation{Object: ptr(""), Relation: ptr(rel)}}
	}
	union := func(us ...openfga.Userset) openfga.Userset {
		return openfga.Userset{Union: &openfga.Usersets{Child: us}}
	}
	direct := func(refs ...openfga.RelationReference) openfga.RelationMetadata {
		return openfga.RelationMetadata{DirectlyRelatedUserTypes: &refs}
	}
	userRef := openfga.RelationReference{Type: "user"}
	tenantRef := openfga.RelationReference{Type: "tenant"}
	assigneeRef := openfga.RelationReference{Type: "role", Relation: ptr("assignee")}
	groupMemberRef := openfga.RelationReference{Type: "group", Relation: ptr("member")}
	rels := func(m map[string]openfga.Userset) *map[string]openfga.Userset { return &m }
	meta := func(m map[string]openfga.RelationMetadata) *openfga.Metadata { return &openfga.Metadata{Relations: &m} }
	return openfga.WriteAuthorizationModelRequest{
		SchemaVersion: "1.1",
		TypeDefinitions: []openfga.TypeDefinition{
			{Type: "user"},
			{Type: "tenant",
				Relations: rels(map[string]openfga.Userset{
					"owner":  {This: this()},
					"admin":  union(openfga.Userset{This: this()}, computed("owner")),
					"member": union(openfga.Userset{This: this()}, computed("admin")),
				}),
				Metadata: meta(map[string]openfga.RelationMetadata{"owner": direct(userRef), "admin": direct(userRef), "member": direct(userRef)}),
			},
			// Feature 004: flat groups; membership grants every role assigned to the group.
			{Type: "group",
				Relations: rels(map[string]openfga.Userset{"tenant": {This: this()}, "member": {This: this()}}),
				Metadata:  meta(map[string]openfga.RelationMetadata{"tenant": direct(tenantRef), "member": direct(userRef)}),
			},
			{Type: "role",
				Relations: rels(map[string]openfga.Userset{"tenant": {This: this()}, "assignee": {This: this()}}),
				Metadata:  meta(map[string]openfga.RelationMetadata{"tenant": direct(tenantRef), "assignee": direct(userRef, groupMemberRef)}),
			},
			{Type: "permission",
				Relations: rels(map[string]openfga.Userset{"tenant": {This: this()}, "granted": {This: this()}}),
				Metadata:  meta(map[string]openfga.RelationMetadata{"tenant": direct(tenantRef), "granted": direct(assigneeRef)}),
			},
		},
	}
}

func ptr(s string) *string { return &s }
