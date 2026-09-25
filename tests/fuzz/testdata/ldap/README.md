# LDAP fuzz/table corpora

Shared inputs for the `internal/ldapdir` table tests (`filter_test.go`,
`dn_test.go`, `mapping_test.go`, URL/target-policy tests) and the fuzz targets
in `services/auth/tests/fuzz/ldap_fuzz_test.go` (T037–T040).

Every file is the **exact input, with no trailing newline** — a trailing
newline changes what a filter/URL parser sees and would silently invalidate
the `valid-*` fixtures. `.editorconfig` is scoped to leave this directory
alone; do not let editors "fix" the files. Files holding non-UTF-8 bytes carry
a `.bin` extension; everything else is UTF-8 text.

## Naming contract

The prefix encodes how `CompileUserFilter` / `ParseDN` / `url.Parse` treat the
content **at the grammar level** — independent of freya policy — so table
tests can glob and assert without surprises:

- `valid-*` — grammar-valid and inside every policy cap (length ≤ 4 KiB,
  depth ≤ 16, ≤ 64 components, valid attribute description and matching
  rule, no NUL; lower-case `:dn:` is allowed). Must be accepted by `ldapdir.CompileUserFilter`.
  `valid-empty.txt` (0 bytes) is the empty-input case → `(objectClass=*)`.
- `invalid-*` — rejected by the underlying grammar itself
  (`ldap.CompileFilter`, `ldap.ParseDN`, `url.Parse`). No freya code runs.
- `injection-*` — attacker value fragments; standalone they must be
  grammar-rejected, and as the user half of `ldapdir.Combine` the combined
  filter must keep a root AND whose first child is the base filter.
- `policy-*` — **grammar-valid but must be refused by freya policy** (caps
  from research D6): `policy-nul-raw.bin` (raw 0x00 byte), `policy-nul-escaped.txt`
  (`\00`), `policy-overlong-6kib.txt` (exactly 6144 bytes), `policy-deep-nesting-16.txt`
  / `policy-deep-nesting-20.txt`, `policy-components-70.txt`, `policy-attr-desc-underscore.txt`,
  `policy-extensible-dn.txt` (`:DN:` in upper case, parsed as a matching rule
  named DN). `ldap.CompileFilter` accepts all of these; only
  freya's policy layer refuses them.
- `odd-*` — grammar-valid edges whose acceptance is a freya policy decision,
  not a grammar fact: empty `(&)`/`(|)`, `(uid=)`, `(uid==x)`, `cn=`, and the
  empty DN (the root DN). Fuzz seeds and "never panics" material; table tests
  must not assert accept/reject from the name alone.
- everything else is named by what it exercises (`scheme-*`, `port-*`,
  `userinfo-*`, `ipv6-*`, `host-*`, …) without claiming an outcome.

## `filters/`

RFC 4515 search filters. `policy-deep-nesting-16.txt` is 16 nested `(&…)`
around `(objectClass=*)` (63 bytes) and `policy-deep-nesting-20.txt` is the
same with 20 (75 bytes) — which side of the depth-16 cap each lands on
depends on how `ldapdir` counts depth; the fuzz targets use both as
never-panic seeds.

## `dns/`

Distinguished names. Scoping expectations are relative to the connection base
`dc=example,dc=test`, matched case-insensitively (research D6):
`under-*` is equal to or a descendant of the base, `outside-*` is not —
including the sibling-suffix trick (`dc=evilexample,dc=test` must not match
`dc=example,dc=test`) and a base extended with another RDN
(`…,dc=example,dc=test,dc=extra` does not end at the base).

## `urls/`

Directory connection URLs for `TargetPolicy.CheckURL` (contract §C): only
`ldap://` and `ldaps://` are in scope. `url.Parse` accepts several hostile
shapes here (`ldap://::1` yields hostname `:` and port `1`,
`ldap://ldap.example.org:389:636` yields hostname `ldap.example.org:389`),
so parsing is never sufficient — that is the point of the corpus.
`ldap://@host` (empty userinfo) and `:pass@host` (password only) parse; it is
`CheckURL`'s job to decide whether credentials may appear in a URL at all.

## `objectguid/`

Raw Active Directory `objectGUID` byte strings (binary). AD stores the first
three GUID groups little-endian (MS-DISO 2.3.4.2), so `valid-sequential.bin`
is the bytes `0x00..0x0f` and must decode to
`03020100-0504-0706-0809-0a0b0c0d0e0f`; `valid-ad-example.bin` must decode to
`3f78f21c-a23e-4c71-9b4e-2d6f9c1a7b55`. `invalid-*` are the wrong lengths
(0/15/17/32) and must be refused, never truncated into a different identity.

## Regenerating

`gen.go` (build tag `ignore`) writes the generated fixtures — the oversized
filter, the 70-component filter, and all `objectguid/*.bin`:

```
cd services/auth/tests/fuzz/testdata/ldap
go run gen.go
```

All other files are static and hand-edited.
