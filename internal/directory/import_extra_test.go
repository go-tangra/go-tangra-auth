package directory

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-freya/freya/services/auth/internal/ldapdir/ldapfake"
)

// A zero result renders every list as [].
func TestImportResultZeroJSON(t *testing.T) {
	js, err := json.Marshal(ImportResult{})
	if err != nil {
		t.Fatal(err)
	}
	if string(js) != `{"created":[],"updated":[],"skipped":[],"failed":[]}` {
		t.Fatalf("zero result = %s", js)
	}
}

// AD: the canonical GUID string is re-fetched as the 16 raw objectGUID
// bytes; a uid that is no GUID is not_found_in_directory without a query.
func TestImportObjectGUID(t *testing.T) {
	f := itSetup(t)
	c, err := f.ms.GetDirectoryConnection(context.Background(), itTenant, itConnID)
	if err != nil {
		t.Fatal(err)
	}
	c.AttrUID = "objectGUID"
	if err := f.ms.UpdateDirectoryConnection(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	raw := []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	const guid = "12345678-9abc-def0-0102-030405060708"
	f.dir.Add(ldapfake.Entry{DN: "cn=Gus," + itBaseDN, Attrs: map[string][][]byte{
		"objectclass": ldapfake.Vals("person"), "objectguid": {raw}, "mail": ldapfake.Vals("gus@example.test"),
	}})

	res := f.importUIDs(t, guid, "not-a-guid", "12345678-9abc-def0-0102-03040506070z")
	if it, ok := itFind(res.Created, guid); !ok || it.UserID == "" {
		t.Fatalf("guid not created: %+v", res)
	}
	for _, u := range []string{"not-a-guid", "12345678-9abc-def0-0102-03040506070z"} {
		if r := itReason(res.Skipped, u); r != ReasonNotFound {
			t.Fatalf("uid %q: reason %q, want %s", u, r, ReasonNotFound)
		}
	}
	if n := len(f.dir.Searches()); n != 1 {
		t.Fatalf("searches = %d, want only the valid guid re-fetched", n)
	}
	if l := f.link(t, guid); l.DirectoryUID != guid {
		t.Fatalf("link uid = %q", l.DirectoryUID)
	}
}

// Two entries answering one unique id import no one.
func TestImportAmbiguousUID(t *testing.T) {
	f := itSetup(t)
	f.itPerson(itBaseDN, "Alice", itAlice, "alice@example.test", "Alice", "A", "")
	f.itPerson(itBaseDN, "Alias", itAlice, "alias@example.test", "Alias", "A", "")

	res := f.importUIDs(t, itAlice)
	if r := itReason(res.Failed, itAlice); r != ReasonDirectoryError {
		t.Fatalf("reason %q, want %s (result %+v)", r, ReasonDirectoryError, res)
	}
	if n := f.userCount(itTenant); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
}
