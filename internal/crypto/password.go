package crypto

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are argon2id parameters. DefaultParams follow the OWASP recommendation.
type Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// DefaultParams: m=19 MiB, t=2, p=1.
var DefaultParams = Params{Memory: 19 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}

// HashPassword returns a PHC-formatted argon2id string.
func HashPassword(password string, p Params) (string, error) {
	if password == "" {
		return "", errors.New("crypto: empty password")
	}
	salt := make([]byte, p.SaltLen)
	if _, err := io.ReadFull(randReader, salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks password against a PHC string. rehash is true when the
// stored parameters are weaker than DefaultParams.
func VerifyPassword(password, encoded string) (ok bool, rehash bool, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, false, errors.New("crypto: unsupported hash format")
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return false, false, errors.New("crypto: malformed parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, false, errors.New("crypto: malformed salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, false, errors.New("crypto: malformed hash")
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(want))) // #nosec G115 -- bounded by decode
	ok = subtle.ConstantTimeCompare(got, want) == 1
	rehash = p.Memory < DefaultParams.Memory || p.Time < DefaultParams.Time
	return ok, rehash, nil
}
