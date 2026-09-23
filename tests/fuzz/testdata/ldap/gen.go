//go:build ignore

// Generates the LDAP corpora under testdata/ldap that are impractical to
// hand-write (see README.md for the full layout):
//
//	go run gen.go
//
// filters/policy-overlong-6kib.txt — a grammar-valid (uid=…) equality filter
// padded to exactly 6144 bytes, i.e. over the 4000-byte CompileUserFilter cap
// and under every other limit, so length is the only reason it is refused.
//
// filters/policy-components-70.txt — a grammar-valid 70-branch (|…) filter,
// over the 64-component policy cap.
//
// objectguid/*.bin — raw Active Directory objectGUID byte strings: 16-byte
// values (valid) and wrong lengths (invalid). AD stores the first three GUID
// groups little-endian (MS-DISO 2.3.4.2); valid-sequential.bin is the bytes
// 0x00..0x0f, which decodes to 03020100-0504-0706-0809-0a0b0c0d0e0f.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

func write(path string, b []byte) {
	if err := os.WriteFile(path, b, 0o644); err != nil { // #nosec G306 -- test fixtures
		panic(err)
	}
	fmt.Printf("%-40s %d bytes\n", path, len(b))
}

// guidBytes encodes a canonical GUID string the way AD stores it in the
// objectGUID attribute: Data1 little-endian uint32, Data2/Data3
// little-endian uint16, Data4 verbatim.
func guidBytes(canonical string) []byte {
	var d1 uint32
	var d2, d3 uint16
	var d4 [8]byte
	if _, err := fmt.Sscanf(canonical, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		&d1, &d2, &d3, &d4[0], &d4[1], &d4[2], &d4[3], &d4[4], &d4[5], &d4[6], &d4[7]); err != nil {
		panic(err)
	}
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], d1)
	binary.LittleEndian.PutUint16(b[4:6], d2)
	binary.LittleEndian.PutUint16(b[6:8], d3)
	copy(b[8:16], d4[:])
	return b
}

func main() {
	// Exactly 6144 bytes: "(uid=" + 6138*"a" + ")".
	overlong := "(uid=" + strings.Repeat("a", 6144-len("(uid=")-len(")")) + ")"
	if len(overlong) != 6144 {
		panic(len(overlong))
	}
	write("filters/policy-overlong-6kib.txt", []byte(overlong))

	var b strings.Builder
	b.WriteString("(|")
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&b, "(uid=u%02d)", i)
	}
	b.WriteString(")")
	write("filters/policy-components-70.txt", []byte(b.String()))

	write("objectguid/valid-zero.bin", make([]byte, 16))
	seq := make([]byte, 16)
	for i := range seq {
		seq[i] = byte(i)
	}
	write("objectguid/valid-sequential.bin", seq)
	write("objectguid/valid-ad-example.bin", guidBytes("3f78f21c-a23e-4c71-9b4e-2d6f9c1a7b55"))
	write("objectguid/valid-all-ff.bin", bytesRepeat(0xff, 16))
	write("objectguid/invalid-empty.bin", nil)
	write("objectguid/invalid-short-15.bin", seq[:15])
	write("objectguid/invalid-long-17.bin", append(seq[:16], 0x10))
	write("objectguid/invalid-double-32.bin", append(append([]byte(nil), seq...), seq...))
}

func bytesRepeat(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}
