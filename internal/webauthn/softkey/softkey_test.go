package softkey

import (
	"encoding/json"
	"testing"
)

func TestOptionsErrors(t *testing.T) {
	k := New("https://auth.example.org")
	for _, in := range []string{"{", `{"publicKey":{}}`} {
		if _, err := k.Create([]byte(in)); err == nil {
			t.Errorf("create %s", in)
		}
		if _, err := k.Get([]byte(in)); err == nil {
			t.Errorf("get %s", in)
		}
	}
	k.UserVerified, k.BackupEligible, k.BackupState = true, true, true
	out, err := k.Get([]byte(`{"publicKey":{"challenge":"AAAA","rpId":"auth.example.org"}}`))
	var v map[string]any
	if err != nil || json.Unmarshal(out, &v) != nil || v["type"] != "public-key" || k.Counter != 1 {
		t.Fatalf("%s %v", out, err)
	}
}
