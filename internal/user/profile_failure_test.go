package user

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-auth/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

var errDown = errors.New("down")

// failUserStore fails the named operations of the in-memory store.
type failUserStore struct {
	*memstore.Store
	fail map[string]bool
}

func (f *failUserStore) User(ctx context.Context, tid, id string) (store.User, error) {
	if f.fail["user"] {
		return store.User{}, errDown
	}
	return f.Store.User(ctx, tid, id)
}
func (f *failUserStore) UpdateProfile(ctx context.Context, tid, id string, p store.ProfilePatch) error {
	if f.fail["update"] {
		return errDown
	}
	if f.fail["user-after-update"] {
		f.fail["user"] = true
	}
	return f.Store.UpdateProfile(ctx, tid, id, p)
}
func (f *failUserStore) LookupProfiles(ctx context.Context, tid string, ids []string) ([]store.PublicProfile, error) {
	if f.fail["lookup"] {
		return nil, errDown
	}
	return f.Store.LookupProfiles(ctx, tid, ids)
}
func (f *failUserStore) SearchProfiles(ctx context.Context, tid, q string, limit int) ([]store.PublicProfile, error) {
	if f.fail["search"] {
		return nil, errDown
	}
	return f.Store.SearchProfiles(ctx, tid, q, limit)
}
func (f *failUserStore) UpsertAvatar(ctx context.Context, a store.Avatar) error {
	if f.fail["upsert"] {
		return errDown
	}
	return f.Store.UpsertAvatar(ctx, a)
}
func (f *failUserStore) DeleteAvatar(ctx context.Context, tid, uid string) error {
	if f.fail["delete"] {
		return errDown
	}
	return f.Store.DeleteAvatar(ctx, tid, uid)
}

func TestProfileAndAvatarFailureBranches(t *testing.T) {
	ctx := context.Background()
	ms := memstore.New()
	ms.AddTenant(store.Tenant{ID: tidP, Slug: "acme", Status: "active", Kind: "customer", Policy: []byte("{}")})
	ms.AddUser(store.User{ID: "u1", TenantID: tidP, Email: "dana@x.test", Status: "active"})
	fs := &failUserStore{Store: ms, fail: map[string]bool{}}
	p := NewProfiles(fs, nil)
	av := NewAvatars(fs, nil, AvatarLimits{}) // zero limits → defaults
	self := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tidP}
	other := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u2", TenantID: tidP, Roles: []string{"member"}}

	// Get: forbidden for a stranger; store outage surfaces as not found (uniform).
	if _, err := p.Get(ctx, other, "u1"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("get by stranger: %v", err)
	}
	fs.fail["user"] = true
	if _, err := p.Get(ctx, self, "u1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get during outage: %v", err)
	}
	if _, err := p.Update(ctx, self, "u1", ProfileUpdate{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update during outage: %v", err)
	}
	fs.fail["user"] = false
	// Update: last name and display name validation, store failures.
	if _, err := p.Update(ctx, self, "u1", ProfileUpdate{LastName: strings.Repeat("x", 101)}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("last name: %v", err)
	}
	bad := "a\x00b"
	if _, err := p.Update(ctx, self, "u1", ProfileUpdate{DisplayName: &bad}); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("display name: %v", err)
	}
	fs.fail["update"] = true
	if _, err := p.Update(ctx, self, "u1", ProfileUpdate{FirstName: "D"}); !errors.Is(err, errDown) {
		t.Fatalf("update failure: %v", err)
	}
	fs.fail["update"] = false
	fs.fail["user-after-update"] = true
	if _, err := p.Update(ctx, self, "u1", ProfileUpdate{FirstName: "D"}); !errors.Is(err, errDown) {
		t.Fatalf("re-read failure: %v", err)
	}
	fs.fail["user-after-update"], fs.fail["user"] = false, false
	// Get succeeds for the owner; a foreign user with a real id is audited and not found.
	if v, err := p.Get(ctx, self, "u1"); err != nil || v.ID != "u1" {
		t.Fatalf("get: %+v %v", v, err)
	}
	const foreign = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99"
	ms.AddUser(store.User{ID: foreign, TenantID: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66", Email: "f@x.test", Status: "active"})
	admin := tenantctx.Actor{Kind: tenantctx.KindUser, UserID: "u1", TenantID: tidP, Roles: []string{"admin"}}
	if _, err := p.Get(ctx, admin, foreign); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign: %v", err)
	}
	// An upload wrapped by http.MaxBytesReader that overflows is "too large".
	rec := httptest.NewRecorder()
	big := http.MaxBytesReader(rec, io.NopCloser(bytes.NewReader(make([]byte, 64))), 16)
	if _, err := NormaliseAvatar(big, AvatarLimits{MaxBytes: 1 << 20}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("max bytes: %v", err)
	}
	// Lookup: store failure and the id cap.
	fs.fail["lookup"] = true
	if _, err := p.Lookup(ctx, self, []string{"u1"}); !errors.Is(err, errDown) {
		t.Fatalf("lookup failure: %v", err)
	}
	fs.fail["lookup"] = false
	many := make([]string, LookupMax+5)
	for i := range many {
		many[i] = "u1"
	}
	if out, err := p.Lookup(ctx, self, many); err != nil || len(out) != LookupMax {
		t.Fatalf("cap: %d %v", len(out), err)
	}
	// DeriveDisplayName fallbacks.
	if DeriveDisplayName("", "", "Prev", "e@x") != "Prev" || DeriveDisplayName("", "", "", "e@x") != "e" || DeriveDisplayName("A", "", "", "e@x") != "A" {
		t.Fatal("derivation")
	}
	// Avatars: defaults apply, store failures surface, strangers are refused.
	png := fixture(t, "valid.png")
	if _, err := av.Set(ctx, other, "u1", bytes.NewReader(png)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("stranger set: %v", err)
	}
	if err := av.Remove(ctx, other, "u1"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("stranger remove: %v", err)
	}
	fs.fail["user"] = true
	if _, err := av.Set(ctx, self, "u1", bytes.NewReader(png)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("set during outage: %v", err)
	}
	if err := av.Remove(ctx, self, "u1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove during outage: %v", err)
	}
	fs.fail["user"] = false
	fs.fail["upsert"] = true
	if _, err := av.Set(ctx, self, "u1", bytes.NewReader(png)); !errors.Is(err, errDown) {
		t.Fatalf("upsert failure: %v", err)
	}
	fs.fail["upsert"] = false
	if _, err := av.Set(ctx, self, "u1", bytes.NewReader(png)); err != nil {
		t.Fatal(err)
	}
	fs.fail["delete"] = true
	if err := av.Remove(ctx, self, "u1"); !errors.Is(err, errDown) {
		t.Fatalf("delete failure: %v", err)
	}
	fs.fail["delete"] = false
	// Decoder: a PNG signature followed by junk fails DecodeConfig.
	if _, err := NormaliseAvatar(bytes.NewReader(append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, []byte("junkjunkjunkjunk")...)), AvatarLimits{}); !errors.Is(err, ErrDecodeFailed) {
		t.Fatalf("junk after signature: %v", err)
	}
	// A reader that fails mid-way is a decode failure.
	if _, err := NormaliseAvatar(failingReader{}, AvatarLimits{}); !errors.Is(err, ErrDecodeFailed) {
		t.Fatalf("reader failure: %v", err)
	}
	// Concurrency 0 means unlimited (no semaphore).
	if _, err := NormaliseAvatar(bytes.NewReader(png), AvatarLimits{Concurrency: 0}); err != nil {
		t.Fatal(err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errDown }
