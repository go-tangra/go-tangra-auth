package ldapdir

import (
	"errors"
	"testing"
)

// pem.Decode skips a malformed block and returns the next good one, so a
// broken block ahead of a valid certificate must still be refused.
func TestParseCARejectsSkippedMalformedBlock(t *testing.T) {
	pki := newTestPKI(t)
	in := "-----BEGIN CERTIFICATE-----\nnot base64 !!\n-----END CERTIFICATE-----\n" + pki.caPEM
	if pool, err := ParseCA(in); !errors.Is(err, ErrInvalidCA) || pool != nil {
		t.Fatalf("ParseCA = (%v, %v), want ErrInvalidCA", pool, err)
	}
}
