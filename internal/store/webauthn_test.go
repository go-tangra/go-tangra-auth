//go:build integration

package store

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestWebAuthnRepos covers the feature 018 store functions under RLS.
func TestWebAuthnRepos(t *testing.T) {
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
	uA, uA2, uB := NewID(), NewID(), NewID()
	if err := st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error {
		for i, id := range []string{tA, tB} {
			if err := InsertTenant(ctx, tx, Tenant{ID: id, Slug: "wa-" + string(rune('a'+i)), DisplayName: "T", Status: "active", Kind: "customer", Policy: []byte("{}")}); err != nil {
				return err
			}
		}
		for _, u := range []User{{ID: uA, TenantID: tA, Email: "a@x.test", Status: "active"}, {ID: uA2, TenantID: tA, Email: "a2@x.test", Status: "active"},
			{ID: uB, TenantID: tB, Email: "b@x.test", Status: "active"}} {
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
	cred := func(uid, tid, name string, id byte) WebAuthnCredential {
		return WebAuthnCredential{ID: NewID(), TenantID: tid, UserID: uid, CredentialID: bytes.Repeat([]byte{id}, 32), PublicKey: []byte{0xa5, 1, 2},
			AAGUID: bytes.Repeat([]byte{7}, 16), SignCount: 3, Transports: []string{"usb", "nfc"}, BackupEligible: false, Name: name}
	}
	k1, k2 := cred(uA, tA, "YubiKey desk", 1), cred(uA, tA, "Travel", 2)
	byID := func(list []WebAuthnCredential, id string) WebAuthnCredential {
		for _, c := range list {
			if c.ID == id {
				return c
			}
		}
		t.Fatalf("key %s not listed in %+v", id, list)
		return WebAuthnCredential{}
	}

	t.Run("handle is created once", func(t *testing.T) {
		var h1, h2, none []byte
		if err := inA(func(tx pgx.Tx) error {
			var err error
			if none, err = WebAuthnHandle(ctx, tx, tA, uA); err != nil {
				return err
			}
			if h1, err = EnsureWebAuthnHandle(ctx, tx, tA, uA, bytes.Repeat([]byte{1}, 32)); err != nil {
				return err
			}
			h2, err = EnsureWebAuthnHandle(ctx, tx, tA, uA, bytes.Repeat([]byte{2}, 32))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if none != nil || !bytes.Equal(h1, h2) || !bytes.Equal(h1, bytes.Repeat([]byte{1}, 32)) {
			t.Fatalf("handles %x %x %x", none, h1, h2)
		}
		if err := inA(func(tx pgx.Tx) error { _, err := EnsureWebAuthnHandle(ctx, tx, tA, uA2, []byte{1, 2}); return err }); err == nil {
			t.Fatal("short handle accepted")
		}
		if err := inA(func(tx pgx.Tx) error {
			_, err := EnsureWebAuthnHandle(ctx, tx, tA, NewID(), bytes.Repeat([]byte{3}, 32))
			return err
		}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown user: %v", err)
		}
		// Another tenant cannot see or set the handle.
		if err := inB(func(tx pgx.Tx) error {
			_, err := EnsureWebAuthnHandle(ctx, tx, tA, uA, bytes.Repeat([]byte{4}, 32))
			return err
		}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign tenant: %v", err)
		}
	})

	t.Run("insert list count", func(t *testing.T) {
		if err := inA(func(tx pgx.Tx) error {
			if err := InsertWebAuthnCredential(ctx, tx, k1); err != nil {
				return err
			}
			return InsertWebAuthnCredential(ctx, tx, k2)
		}); err != nil {
			t.Fatal(err)
		}
		var got []WebAuthnCredential
		_ = inA(func(tx pgx.Tx) error { got, err = ListWebAuthnCredentials(ctx, tx, tA, uA); return err })
		g := byID(got, k1.ID)
		if len(got) != 2 || g.Name != "YubiKey desk" || !bytes.Equal(g.CredentialID, k1.CredentialID) || !bytes.Equal(g.PublicKey, k1.PublicKey) || g.SignCount != 3 ||
			!slices.Equal(g.Transports, []string{"usb", "nfc"}) || !bytes.Equal(g.AAGUID, k1.AAGUID) || g.LastUsedAt != nil || g.CloneFlaggedAt != nil || g.CreatedAt.IsZero() ||
			g.TenantID != tA || g.UserID != uA {
			t.Fatalf("%+v", got)
		}
		var n int
		_ = st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error { n, err = CountAllWebAuthnCredentials(ctx, tx); return err })
		if n != 2 {
			t.Fatalf("count %d", n)
		}
	})

	t.Run("uniqueness and bounds", func(t *testing.T) {
		dup := cred(uA2, tA, "Other", 1) // same credential id, other user
		if err := inA(func(tx pgx.Tx) error { return InsertWebAuthnCredential(ctx, tx, dup) }); !errors.Is(err, ErrCredentialExists) {
			t.Fatalf("duplicate credential id: %v", err)
		}
		sameName := cred(uA, tA, "yubikey DESK", 3) // case-insensitive per user
		if err := inA(func(tx pgx.Tx) error { return InsertWebAuthnCredential(ctx, tx, sameName) }); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate name: %v", err)
		}
		other := cred(uA2, tA, "YubiKey desk", 4) // same name, other user: fine
		if err := inA(func(tx pgx.Tx) error { return InsertWebAuthnCredential(ctx, tx, other) }); err != nil {
			t.Fatal(err)
		}
		for name, c := range map[string]WebAuthnCredential{
			"short id":       func() WebAuthnCredential { c := cred(uA, tA, "x1", 5); c.CredentialID = []byte{1, 2, 3}; return c }(),
			"long id":        func() WebAuthnCredential { c := cred(uA, tA, "x2", 6); c.CredentialID = make([]byte, 1024); return c }(),
			"empty name":     cred(uA, tA, "", 7),
			"long name":      cred(uA, tA, string(bytes.Repeat([]byte{'n'}, 65)), 8),
			"bad aaguid":     func() WebAuthnCredential { c := cred(uA, tA, "x3", 9); c.AAGUID = []byte{1}; return c }(),
			"transports":     func() WebAuthnCredential { c := cred(uA, tA, "x4", 10); c.Transports = make([]string, 9); return c }(),
			"public key":     func() WebAuthnCredential { c := cred(uA, tA, "x5", 11); c.PublicKey = make([]byte, 2049); return c }(),
			"negative count": func() WebAuthnCredential { c := cred(uA, tA, "x6", 12); c.SignCount = -1; return c }(),
		} {
			if err := inA(func(tx pgx.Tx) error { return InsertWebAuthnCredential(ctx, tx, c) }); err == nil {
				t.Errorf("%s accepted", name)
			}
		}
	})

	t.Run("rename use flag delete", func(t *testing.T) {
		if err := inA(func(tx pgx.Tx) error { return RenameWebAuthnCredential(ctx, tx, tA, uA, k2.ID, "travel key") }); err != nil {
			t.Fatal(err)
		}
		if err := inA(func(tx pgx.Tx) error { return RenameWebAuthnCredential(ctx, tx, tA, uA, k2.ID, "YUBIKEY desk") }); !errors.Is(err, ErrConflict) {
			t.Fatalf("rename onto a taken name: %v", err)
		}
		if err := inA(func(tx pgx.Tx) error { return RenameWebAuthnCredential(ctx, tx, tA, uA2, k2.ID, "mine now") }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("rename another user's key: %v", err)
		}
		if err := inA(func(tx pgx.Tx) error { return UpdateWebAuthnUse(ctx, tx, tA, k1.ID, 9, true) }); err != nil {
			t.Fatal(err)
		}
		if err := inA(func(tx pgx.Tx) error { return FlagWebAuthnClone(ctx, tx, tA, k2.ID) }); err != nil {
			t.Fatal(err)
		}
		for _, fn := range []func(tx pgx.Tx) error{
			func(tx pgx.Tx) error { return UpdateWebAuthnUse(ctx, tx, tA, NewID(), 1, false) },
			func(tx pgx.Tx) error { return FlagWebAuthnClone(ctx, tx, tA, NewID()) },
		} {
			if err := inA(fn); !errors.Is(err, ErrNotFound) {
				t.Fatalf("unknown key: %v", err)
			}
		}
		var got []WebAuthnCredential
		_ = inA(func(tx pgx.Tx) error { got, err = ListWebAuthnCredentials(ctx, tx, tA, uA); return err })
		if g1, g2 := byID(got, k1.ID), byID(got, k2.ID); g1.SignCount != 9 || !g1.BackupState || g1.LastUsedAt == nil || g2.Name != "travel key" || g2.CloneFlaggedAt == nil || g2.LastUsedAt != nil {
			t.Fatalf("%+v", got)
		}
		if err := inA(func(tx pgx.Tx) error { return DeleteWebAuthnCredential(ctx, tx, tA, uA2, k2.ID) }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete another user's key: %v", err)
		}
		if err := inA(func(tx pgx.Tx) error { return DeleteWebAuthnCredential(ctx, tx, tA, uA, k2.ID) }); err != nil {
			t.Fatal(err)
		}
		_ = inA(func(tx pgx.Tx) error { got, err = ListWebAuthnCredentials(ctx, tx, tA, uA); return err })
		if len(got) != 1 {
			t.Fatalf("%+v", got)
		}
	})

	t.Run("rls isolation", func(t *testing.T) {
		var got []WebAuthnCredential
		if err := inB(func(tx pgx.Tx) error { got, err = ListWebAuthnCredentials(ctx, tx, tA, uA); return err }); err != nil || len(got) != 0 {
			t.Fatalf("foreign tenant sees keys: %v %v", got, err)
		}
		if err := inB(func(tx pgx.Tx) error { return DeleteWebAuthnCredential(ctx, tx, tA, uA, k1.ID) }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign delete: %v", err)
		}
		// Inserting a row for tenant A from tenant B's scope is refused by the policy.
		if err := inB(func(tx pgx.Tx) error { return InsertWebAuthnCredential(ctx, tx, cred(uA, tA, "sneaky", 20)) }); err == nil {
			t.Fatal("cross-tenant insert accepted")
		}
	})

	t.Run("reset and cascade", func(t *testing.T) {
		kb := cred(uB, tB, "B key", 30)
		if err := inB(func(tx pgx.Tx) error {
			if err := SetMFA(ctx, tx, tB, uB, true, []byte("sealed")); err != nil {
				return err
			}
			if err := ReplaceRecoveryCodes(ctx, tx, tB, uB, []string{"h1", "h2"}); err != nil {
				return err
			}
			return InsertWebAuthnCredential(ctx, tx, kb)
		}); err != nil {
			t.Fatal(err)
		}
		if err := inB(func(tx pgx.Tx) error { return ResetMFA(ctx, tx, tB, uB) }); err != nil {
			t.Fatal(err)
		}
		var u User
		var keys []WebAuthnCredential
		var codes []string
		_ = inB(func(tx pgx.Tx) error {
			u, _ = GetUser(ctx, tx, tB, uB)
			keys, _ = ListWebAuthnCredentials(ctx, tx, tB, uB)
			codes, _ = ListRecoveryCodeHashes(ctx, tx, tB, uB)
			return nil
		})
		if u.MFAEnabled || u.MFASecretEnc != nil || len(keys) != 0 || len(codes) != 0 {
			t.Fatalf("reset left %+v %v %v", u, keys, codes)
		}
		if err := inB(func(tx pgx.Tx) error { return ResetMFA(ctx, tx, tB, NewID()) }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("reset unknown user: %v", err)
		}
		// The break-glass reset removes keys too.
		if err := inA(func(tx pgx.Tx) error { return ResetCredentials(ctx, tx, tA, uA) }); err != nil {
			t.Fatal(err)
		}
		_ = inA(func(tx pgx.Tx) error { keys, _ = ListWebAuthnCredentials(ctx, tx, tA, uA); return nil })
		if len(keys) != 0 {
			t.Fatalf("reset-user kept keys: %+v", keys)
		}
		// Deleting a user cascades to their keys.
		if err := st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "DELETE FROM users WHERE id = $1", uA2)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var n int
		_ = st.Tx(ctx, Scope{System: true}, func(tx pgx.Tx) error { n, err = CountAllWebAuthnCredentials(ctx, tx); return err })
		if n != 0 {
			t.Fatalf("keys left %d", n)
		}
	})
}
