package crypto

import (
	"bytes"
	"errors"
	"testing"
)

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestRandomnessFailures(t *testing.T) {
	restore := SetRand(badReader{})
	defer restore()
	if _, err := RandomToken(16); err == nil {
		t.Fatal("RandomToken must fail without entropy")
	}
	if _, err := HashPassword("x", DefaultParams); err == nil {
		t.Fatal("HashPassword must fail without entropy")
	}
	restore()
	env, _ := NewEnvelope(bytes.Repeat([]byte{1}, 32))
	restore = SetRand(badReader{})
	if _, err := env.Encrypt([]byte("x"), nil); err == nil {
		t.Fatal("Encrypt must fail without entropy")
	}
	restore()
	if Rand() == nil {
		t.Fatal("rand restored")
	}
}
