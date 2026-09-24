package directory

import (
	"encoding/json"
	"testing"
)

// The wire form decodes back to the same result (null → "").
func TestSearchResultJSONRoundTrip(t *testing.T) {
	in := SearchResult{
		Items: []SearchItem{
			{UID: "u1", DN: "uid=a," + ttBaseDN, DisplayName: "A", Status: StatusNew},
			{UID: "u2", DN: "uid=b," + ttBaseDN, Email: "b@example.test", Status: StatusImported, UserID: stUserImported},
			{DN: "uid=c," + ttBaseDN, Status: StatusInvalid, Reason: "multi_valued_uid"},
		},
		Truncated: true, OutOfScope: 1, EffectiveFilter: "(&(objectClass=*)(objectClass=*))",
	}
	js, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out SearchResult
	if err := json.Unmarshal(js, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != len(in.Items) || out.Truncated != in.Truncated || out.OutOfScope != in.OutOfScope || out.EffectiveFilter != in.EffectiveFilter {
		t.Fatalf("round trip %+v", out)
	}
	for i := range in.Items {
		if out.Items[i] != in.Items[i] {
			t.Fatalf("item %d: %+v, want %+v", i, out.Items[i], in.Items[i])
		}
	}
	var it SearchItem
	if err := it.UnmarshalJSON([]byte(`[]`)); err == nil {
		t.Fatal("want an error for a non-object item")
	}
}

// A store failure while reading preview statuses is a generic error: no
// partial result, no ok audit row, the session closed.
func TestSearchPreviewStoreFailure(t *testing.T) {
	for _, method := range []string{"LinksByUIDs", "UsersByEmails"} {
		t.Run(method, func(t *testing.T) {
			f := stSetup(t, ttOpts{})
			f.ms.FailNext(method)
			res, err := f.search(SearchRequest{Filter: "(objectClass=person)"})
			if err == nil || len(res.Items) != 0 {
				t.Fatalf("res %+v err %v, want an error and no items", res, err)
			}
			ttNoSecretErr(t, "search", err)
			if n := f.dir.OpenSessions(); n != 0 {
				t.Fatalf("%d sessions left open", n)
			}
			for _, r := range f.searched(t) {
				if r.Outcome == "ok" {
					t.Fatal("a failed preview must not be audited as ok")
				}
			}
		})
	}
}
