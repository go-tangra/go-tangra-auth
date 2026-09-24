package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

func conn(tid, id, name string) store.DirectoryConnection {
	return store.DirectoryConnection{ID: id, TenantID: tid, Name: name, Kind: "openldap", URL: "ldaps://h", TLSMode: "ldaps",
		BindDN: "cn=a", BindPasswordEnc: []byte("sealed"), BaseDN: "dc=a", AttrUID: "entryUUID", AttrEmail: "mail", AttrDisplayName: "cn",
		SizeLimit: 500, TimeLimitSeconds: 15}
}

func ptr(s string) *string { return &s }

func TestDirectoryConnections(t *testing.T) {
	ctx := context.Background()
	m := New()
	if err := m.InsertDirectoryConnection(ctx, conn("t1", "c1", "Corp")); err != nil {
		t.Fatal(err)
	}
	if err := m.InsertDirectoryConnection(ctx, conn("t1", "c2", "corp")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	if err := m.InsertDirectoryConnection(ctx, conn("t2", "c3", "CORP")); err != nil {
		t.Fatalf("other tenant same name: %v", err)
	}
	if err := m.InsertDirectoryConnection(ctx, conn("t1", "c4", "alpha")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetDirectoryConnection(ctx, "t2", "c1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if c, err := m.GetDirectoryConnectionAnyTenant(ctx, "c1"); err != nil || c.TenantID != "t1" {
		t.Fatalf("any tenant: %v %+v", err, c)
	}
	list, _ := m.ListDirectoryConnections(ctx, "t1")
	if len(list) != 2 || list[0].ID != "c4" || list[1].ID != "c1" {
		t.Fatalf("list order: %+v", list)
	}
	if n, _ := m.CountDirectoryConnections(ctx, "t1"); n != 2 {
		t.Fatalf("count %d", n)
	}

	at := time.Unix(100, 0)
	if err := m.SetDirectoryConnectionTest(ctx, "t1", "c1", "ok", at); err != nil {
		t.Fatal(err)
	}
	if err := m.SetDirectoryConnectionTest(ctx, "t2", "c1", "ok", at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant test: %v", err)
	}
	up := conn("t1", "c1", "Corp2")
	up.BindPasswordEnc, up.UpdatedBy = nil, ptr("admin")
	if err := m.UpdateDirectoryConnection(ctx, up); err != nil {
		t.Fatal(err)
	}
	got, _ := m.GetDirectoryConnection(ctx, "t1", "c1")
	if got.Name != "Corp2" || string(got.BindPasswordEnc) != "sealed" || got.LastTestOutcome == nil || *got.LastTestOutcome != "ok" || *got.UpdatedBy != "admin" {
		t.Fatalf("update kept fields wrong: %+v", got)
	}
	if err := m.UpdateDirectoryConnection(ctx, conn("t1", "c1", "ALPHA")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("rename onto existing: %v", err)
	}
	if err := m.UpdateDirectoryConnection(ctx, conn("t2", "c1", "x")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	got.BindPasswordEnc[0] = 'X'
	if again, _ := m.GetDirectoryConnection(ctx, "t1", "c1"); string(again.BindPasswordEnc) != "sealed" {
		t.Fatal("returned ciphertext aliases stored state")
	}
	if err := m.DeleteDirectoryConnection(ctx, "t2", "c1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
}

func TestDirectoryLinksAndImportedUsers(t *testing.T) {
	ctx := context.Background()
	m := New()
	_ = m.InsertDirectoryConnection(ctx, conn("t1", "c1", "Corp"))
	m.AddUser(store.User{ID: "u1", TenantID: "t1", Email: "a@x.test", Status: "imported"})
	m.AddUser(store.User{ID: "u2", TenantID: "t1", Email: "b@x.test", Status: "imported"})
	m.AddUser(store.User{ID: "u3", TenantID: "t1", Email: "c@x.test", Status: "active"})

	users, _ := m.UsersByEmails(ctx, "t1", []string{"A@X.test", "nobody@x.test"})
	if len(users) != 1 || users["a@x.test"].ID != "u1" {
		t.Fatalf("UsersByEmails: %+v", users)
	}

	t0, t1 := time.Unix(10, 0), time.Unix(20, 0)
	l := store.DirectoryLink{UserID: "u1", TenantID: "t1", ConnectionID: ptr("c1"), ConnectionName: "Corp", DirectoryUID: "uid-1", DirectoryDN: "uid=a", FirstImportedAt: t0, LastImportedAt: t0}
	if err := m.UpsertLink(ctx, l); err != nil {
		t.Fatal(err)
	}
	dup := l
	dup.UserID = "u2"
	if err := m.UpsertLink(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("uid linked twice: %v", err)
	}
	missing := l
	missing.UserID = "nope"
	if err := m.UpsertLink(ctx, missing); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	l.FirstImportedAt, l.LastImportedAt = t1, t1
	if err := m.UpsertLink(ctx, l); err != nil {
		t.Fatal(err)
	}
	links, _ := m.LinksByUIDs(ctx, "t1", "c1", []string{"uid-1", "uid-x"})
	if got := links["uid-1"]; len(links) != 1 || !got.FirstImportedAt.Equal(t0) || !got.LastImportedAt.Equal(t1) {
		t.Fatalf("LinksByUIDs / first_imported_at kept: %+v", links)
	}

	// Status guard and e-mail uniqueness on refresh.
	if err := m.UpdateImportedUser(ctx, "t1", "u3", store.ImportedProfile{Email: "c@x.test"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("non-imported refresh: %v", err)
	}
	if err := m.UpdateImportedUser(ctx, "t1", "u1", store.ImportedProfile{Email: "B@x.test"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("e-mail in use: %v", err)
	}
	if err := m.UpdateImportedUser(ctx, "t1", "u1", store.ImportedProfile{Email: "new@x.test", DisplayName: "New"}); err != nil {
		t.Fatal(err)
	}
	if u, err := m.UserByEmail(ctx, "t1", "new@x.test"); err != nil || u.ID != "u1" || u.DisplayName != "New" {
		t.Fatalf("refreshed user: %v %+v", err, u)
	}
	if _, err := m.UserByEmail(ctx, "t1", "a@x.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("old e-mail key left behind")
	}

	// ListUsers carries the origin; SET NULL on connection delete keeps the name.
	list, _ := m.ListUsers(ctx, "t1", "new@", "", 0)
	if len(list) != 1 || list[0].Directory == nil || list[0].Directory.DirectoryUID != "uid-1" {
		t.Fatalf("ListUsers origin: %+v", list)
	}
	if err := m.DeleteDirectoryConnection(ctx, "t1", "c1"); err != nil {
		t.Fatal(err)
	}
	list, _ = m.ListUsers(ctx, "t1", "new@", "", 0)
	if d := list[0].Directory; d == nil || d.ConnectionID != nil || d.ConnectionName != "Corp" {
		t.Fatalf("SET NULL: %+v", d)
	}

	// Delete: only while imported; the link cascades.
	if err := m.DeleteImportedUser(ctx, "t1", "u3"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete active: %v", err)
	}
	if err := m.DeleteImportedUser(ctx, "t2", "u1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if err := m.DeleteImportedUser(ctx, "t1", "u1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.dir.links["u1"]; ok {
		t.Fatal("link not cascaded")
	}
	if _, err := m.User(ctx, "t1", "u1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("user not deleted")
	}
}

func TestListUsersPendingInvitation(t *testing.T) {
	ctx := context.Background()
	m := New()
	now := time.Now()
	m.AddUser(store.User{ID: "u1", TenantID: "t1", Email: "i@x.test", Status: "invited"})
	m.AddUser(store.User{ID: "u2", TenantID: "t1", Email: "a@x.test", Status: "active"})
	_ = m.InsertInvitation(ctx, store.Invitation{ID: "old", TenantID: "t1", Email: "i@x.test", ExpiresAt: now.Add(-time.Hour)})
	_ = m.InsertInvitation(ctx, store.Invitation{ID: "new", TenantID: "t1", Email: "I@x.test", ExpiresAt: now.Add(time.Hour)})
	_ = m.InsertInvitation(ctx, store.Invitation{ID: "rev", TenantID: "t1", Email: "i@x.test", ExpiresAt: now.Add(2 * time.Hour), RevokedAt: &now})
	_ = m.InsertInvitation(ctx, store.Invitation{ID: "act", TenantID: "t1", Email: "a@x.test", ExpiresAt: now.Add(time.Hour)})
	list, _ := m.ListUsers(ctx, "t1", "", "", 0)
	for _, u := range list {
		switch u.ID {
		case "u1":
			if u.InvitationID == nil || *u.InvitationID != "new" {
				t.Fatalf("pending invitation: %v", u.InvitationID)
			}
		case "u2":
			if u.InvitationID != nil || u.Directory != nil {
				t.Fatalf("active user got origin fields: %+v", u)
			}
		}
	}
}

func TestFailNext(t *testing.T) {
	ctx := context.Background()
	m := New()
	m.FailNext("InsertDirectoryConnection")
	if err := m.InsertDirectoryConnection(ctx, conn("t1", "c1", "Corp")); err == nil {
		t.Fatal("expected injected error")
	}
	if n, _ := m.CountDirectoryConnections(ctx, "t1"); n != 0 {
		t.Fatal("injected failure changed state")
	}
	if err := m.InsertDirectoryConnection(ctx, conn("t1", "c1", "Corp")); err != nil {
		t.Fatalf("FailNext not disarmed: %v", err)
	}
	for _, name := range []string{"GetDirectoryConnection", "GetDirectoryConnectionAnyTenant", "ListDirectoryConnections", "CountDirectoryConnections",
		"UpdateDirectoryConnection", "SetDirectoryConnectionTest", "DeleteDirectoryConnection", "UsersByEmails", "LinksByUIDs", "UpsertLink",
		"UpdateImportedUser", "DeleteImportedUser"} {
		m.FailNext(name)
	}
	errs := []error{}
	_, err := m.GetDirectoryConnection(ctx, "t1", "c1")
	errs = append(errs, err)
	_, err = m.GetDirectoryConnectionAnyTenant(ctx, "c1")
	errs = append(errs, err)
	_, err = m.ListDirectoryConnections(ctx, "t1")
	errs = append(errs, err)
	_, err = m.CountDirectoryConnections(ctx, "t1")
	errs = append(errs, err, m.UpdateDirectoryConnection(ctx, conn("t1", "c1", "Corp")),
		m.SetDirectoryConnectionTest(ctx, "t1", "c1", "ok", time.Now()), m.DeleteDirectoryConnection(ctx, "t1", "c1"))
	_, err = m.UsersByEmails(ctx, "t1", nil)
	errs = append(errs, err)
	_, err = m.LinksByUIDs(ctx, "t1", "c1", nil)
	errs = append(errs, err, m.UpsertLink(ctx, store.DirectoryLink{}), m.UpdateImportedUser(ctx, "t1", "u", store.ImportedProfile{}), m.DeleteImportedUser(ctx, "t1", "u"))
	for i, e := range errs {
		var inj injectedErr
		if !errors.As(e, &inj) {
			t.Errorf("call %d: want injected error, got %v", i, e)
		}
	}
	if _, err := m.GetDirectoryConnection(ctx, "t1", "c1"); err != nil {
		t.Fatalf("connection should survive injected delete: %v", err)
	}
}
