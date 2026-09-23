//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestDirectoryRepos covers the feature 016 store functions under RLS and the
// ListUsers origin / pending-invitation join.
func TestDirectoryRepos(t *testing.T) {
	adminDSN, appDSN := startDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, adminDSN); err != nil {
		t.Fatal(err)
	}
	st, err := Open(ctx, appDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tA, tB := NewID(), NewID()
	actor := NewID()
	uImp, uImp2, uAct, uInv := NewID(), NewID(), NewID(), NewID()
	if err := st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error {
		for i, id := range []string{tA, tB} {
			if err := InsertTenant(ctx, tx, Tenant{ID: id, Slug: "dir-" + string(rune('a'+i)), DisplayName: "T", Status: "active", Kind: "customer", Policy: []byte("{}")}); err != nil {
				return err
			}
		}
		for _, u := range []User{
			{ID: uImp, TenantID: tA, Email: "imp@x.test", Status: "imported", DisplayName: "Imp"},
			{ID: uImp2, TenantID: tA, Email: "imp2@x.test", Status: "imported"},
			{ID: uAct, TenantID: tA, Email: "act@x.test", Status: "active"},
			{ID: uInv, TenantID: tA, Email: "inv@x.test", Status: "invited"},
		} {
			if err := InsertUser(ctx, tx, u); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	inA := func(fn func(tx pgx.Tx) error) error { return st.Tx(ctx, Scope{TenantID: tA}, fn) }
	inB := func(fn func(tx pgx.Tx) error) error { return st.Tx(ctx, Scope{TenantID: tB}, fn) }

	conn := DirectoryConnection{ID: NewID(), TenantID: tA, Name: "Corp", Kind: "openldap", URL: "ldaps://ldap.example.test", TLSMode: "ldaps",
		BindDN: "cn=reader,dc=example,dc=test", BindPasswordEnc: []byte{1, 2, 3}, BaseDN: "dc=example,dc=test",
		AttrUID: "entryUUID", AttrEmail: "mail", AttrDisplayName: "cn", AttrFirstName: "givenName", AttrLastName: "sn",
		SizeLimit: 500, TimeLimitSeconds: 15, CreatedBy: &actor}

	t.Run("connection crud", func(t *testing.T) {
		if err := inA(func(tx pgx.Tx) error { return InsertDirectoryConnection(ctx, tx, conn) }); err != nil {
			t.Fatal(err)
		}
		dup := conn
		dup.ID, dup.Name = NewID(), "CORP"
		if err := inA(func(tx pgx.Tx) error { return InsertDirectoryConnection(ctx, tx, dup) }); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate name: %v, want ErrConflict", err)
		}
		var got DirectoryConnection
		var n int
		var list []DirectoryConnection
		if err := inA(func(tx pgx.Tx) (err error) {
			if got, err = GetDirectoryConnection(ctx, tx, tA, conn.ID); err != nil {
				return err
			}
			if n, err = CountDirectoryConnections(ctx, tx, tA); err != nil {
				return err
			}
			list, err = ListDirectoryConnections(ctx, tx, tA)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if got.CAPEM != "" || got.SizeLimit != 500 || string(got.BindPasswordEnc) != "\x01\x02\x03" || got.CreatedBy == nil || *got.CreatedBy != actor || got.LastTestOutcome != nil {
			t.Fatalf("got %+v", got)
		}
		if n != 1 || len(list) != 1 {
			t.Fatalf("count %d list %d", n, len(list))
		}
		// Tenant B sees nothing.
		if err := inB(func(tx pgx.Tx) error { _, err := GetDirectoryConnection(ctx, tx, tA, conn.ID); return err }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-tenant get: %v", err)
		}
		// Update without a password keeps it; with CA and new name.
		up := conn
		up.Name, up.CAPEM, up.BindPasswordEnc, up.UpdatedBy, up.SizeLimit = "Corp 2", "PEM", nil, &actor, 100
		if err := inA(func(tx pgx.Tx) error { return UpdateDirectoryConnection(ctx, tx, up) }); err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Truncate(time.Microsecond)
		if err := inA(func(tx pgx.Tx) error { return SetDirectoryConnectionTest(ctx, tx, tA, conn.ID, "ok", at) }); err != nil {
			t.Fatal(err)
		}
		if err := inA(func(tx pgx.Tx) (err error) { got, err = GetDirectoryConnection(ctx, tx, tA, conn.ID); return err }); err != nil {
			t.Fatal(err)
		}
		if got.Name != "Corp 2" || got.CAPEM != "PEM" || got.SizeLimit != 100 || string(got.BindPasswordEnc) != "\x01\x02\x03" ||
			got.LastTestOutcome == nil || *got.LastTestOutcome != "ok" || !got.LastTestAt.Equal(at) {
			t.Fatalf("after update: %+v", got)
		}
		up.BindPasswordEnc = []byte{9}
		if err := inA(func(tx pgx.Tx) error { return UpdateDirectoryConnection(ctx, tx, up) }); err != nil {
			t.Fatal(err)
		}
		if err := inA(func(tx pgx.Tx) (err error) { got, err = GetDirectoryConnection(ctx, tx, tA, conn.ID); return err }); err != nil {
			t.Fatal(err)
		}
		if string(got.BindPasswordEnc) != "\x09" {
			t.Fatal("password not replaced")
		}
		missing := up
		missing.ID = NewID()
		if err := inA(func(tx pgx.Tx) error { return UpdateDirectoryConnection(ctx, tx, missing) }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("update missing: %v", err)
		}
		if err := inA(func(tx pgx.Tx) error { return SetDirectoryConnectionTest(ctx, tx, tA, missing.ID, "ok", at) }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("set-test missing: %v", err)
		}
		if err := st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error { _, err := GetDirectoryConnectionAnyTenant(ctx, tx, conn.ID); return err }); err != nil {
			t.Fatalf("any tenant: %v", err)
		}
	})

	t.Run("links, users and imported guards", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		link := DirectoryLink{UserID: uImp, TenantID: tA, ConnectionID: &conn.ID, ConnectionName: "Corp 2", DirectoryUID: "uid-1",
			DirectoryDN: "uid=a,dc=example,dc=test", FirstImportedAt: now, LastImportedAt: now, ImportedBy: &actor}
		if err := inA(func(tx pgx.Tx) error { return UpsertLink(ctx, tx, link) }); err != nil {
			t.Fatal(err)
		}
		later := now.Add(time.Hour)
		link.LastImportedAt, link.FirstImportedAt, link.DirectoryDN = later, later, "uid=b,dc=example,dc=test"
		if err := inA(func(tx pgx.Tx) error { return UpsertLink(ctx, tx, link) }); err != nil {
			t.Fatal(err)
		}
		other := link
		other.UserID = uImp2
		if err := inA(func(tx pgx.Tx) error { return UpsertLink(ctx, tx, other) }); !errors.Is(err, ErrConflict) {
			t.Fatalf("same uid on another user: %v, want ErrConflict", err)
		}
		var links map[string]DirectoryLink
		var users map[string]User
		if err := inA(func(tx pgx.Tx) (err error) {
			if links, err = LinksByUIDs(ctx, tx, tA, conn.ID, []string{"uid-1", "uid-x"}); err != nil {
				return err
			}
			users, err = UsersByEmails(ctx, tx, tA, []string{"IMP@x.test", "act@x.test", "none@x.test"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		l, ok := links["uid-1"]
		if len(links) != 1 || !ok || !l.FirstImportedAt.Equal(now) || !l.LastImportedAt.Equal(later) || l.DirectoryDN != "uid=b,dc=example,dc=test" {
			t.Fatalf("links %+v", links)
		}
		if len(users) != 2 || users["imp@x.test"].ID != uImp || users["act@x.test"].ID != uAct {
			t.Fatalf("users by emails: %d", len(users))
		}
		if err := inB(func(tx pgx.Tx) (err error) {
			links, err = LinksByUIDs(ctx, tx, tA, conn.ID, []string{"uid-1"})
			return err
		}); err != nil || len(links) != 0 {
			t.Fatalf("cross-tenant links: %v %d", err, len(links))
		}

		p := ImportedProfile{Email: "imp-new@x.test", DisplayName: "New", FirstName: "N", LastName: "W", DisplayNameExplicit: true}
		if err := inA(func(tx pgx.Tx) error { return UpdateImportedUser(ctx, tx, tA, uImp, p) }); err != nil {
			t.Fatal(err)
		}
		if err := inA(func(tx pgx.Tx) error { return UpdateImportedUser(ctx, tx, tA, uAct, p) }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("update active user: %v, want ErrNotFound", err)
		}
		p.Email = "act@x.test"
		if err := inA(func(tx pgx.Tx) error { return UpdateImportedUser(ctx, tx, tA, uImp2, p) }); !errors.Is(err, ErrConflict) {
			t.Fatalf("email in use: %v, want ErrConflict", err)
		}
		if err := inA(func(tx pgx.Tx) error { return DeleteImportedUser(ctx, tx, tA, uAct) }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete active user: %v, want ErrNotFound", err)
		}
		if err := inB(func(tx pgx.Tx) error { return DeleteImportedUser(ctx, tx, tA, uImp2) }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-tenant delete: %v", err)
		}
		if err := inA(func(tx pgx.Tx) error { return DeleteImportedUser(ctx, tx, tA, uImp2) }); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("list users origin and invitation", func(t *testing.T) {
		invOld, invNew, invRevoked := NewID(), NewID(), NewID()
		if err := inA(func(tx pgx.Tx) error {
			for i, id := range []string{invOld, invNew, invRevoked} {
				if err := InsertInvitation(ctx, tx, Invitation{ID: id, TenantID: tA, Email: "inv@x.test", TokenHash: id, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
					return err
				}
				// Distinct created_at so "most recent" is well defined.
				if _, err := tx.Exec(ctx, "UPDATE invitations SET created_at = now() + make_interval(secs => $2) WHERE id = $1", id, i); err != nil {
					return err
				}
			}
			_, err := tx.Exec(ctx, "UPDATE invitations SET revoked_at = now() WHERE id = $1", invRevoked)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var list []User
		if err := inA(func(tx pgx.Tx) (err error) { list, err = ListUsers(ctx, tx, tA, "", "", 50); return err }); err != nil {
			t.Fatal(err)
		}
		by := map[string]User{}
		for _, u := range list {
			by[u.ID] = u
		}
		if len(list) != 3 {
			t.Fatalf("list: %d users", len(list))
		}
		imp := by[uImp]
		if imp.Directory == nil || imp.Directory.ConnectionName != "Corp 2" || imp.Directory.DirectoryUID != "uid-1" || imp.Email != "imp-new@x.test" || imp.InvitationID != nil {
			t.Fatalf("imported user: %+v", imp)
		}
		if inv := by[uInv]; inv.InvitationID == nil || *inv.InvitationID != invNew || inv.Directory != nil {
			t.Fatalf("invited user invitation: %+v", inv)
		}
		if act := by[uAct]; act.Directory != nil || act.InvitationID != nil {
			t.Fatalf("active user: %+v", act)
		}
		if err := inA(func(tx pgx.Tx) (err error) { list, err = ListUsers(ctx, tx, tA, "", "imported", 50); return err }); err != nil || len(list) != 1 || list[0].ID != uImp {
			t.Fatalf("status=imported: %v %d", err, len(list))
		}
		// Connection delete keeps the origin label with a NULL connection id.
		if err := inA(func(tx pgx.Tx) error { return DeleteDirectoryConnection(ctx, tx, tA, conn.ID) }); err != nil {
			t.Fatal(err)
		}
		if err := inA(func(tx pgx.Tx) error { return DeleteDirectoryConnection(ctx, tx, tA, conn.ID) }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("second delete: %v", err)
		}
		if err := inA(func(tx pgx.Tx) (err error) { list, err = ListUsers(ctx, tx, tA, "imp", "imported", 50); return err }); err != nil || len(list) != 1 {
			t.Fatalf("after delete: %v %d", err, len(list))
		}
		if d := list[0].Directory; d == nil || d.ConnectionID != nil || d.ConnectionName != "Corp 2" {
			t.Fatalf("origin after connection delete: %+v", d)
		}
	})
}
