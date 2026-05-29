// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/systems"
)

// newStore opens a fresh temp DB and initialises systems, groups,
// and credentials stores in that order. systems + groups must
// exist before credentials because credentials' migration installs
// cascade triggers on hosts and system_groups.
func newStore(t *testing.T) *SQLiteStore {
	t.Helper()
	store, _, _, _ := newStoreWithSiblings(t)
	return store
}

func newStoreWithSiblings(t *testing.T) (*SQLiteStore, *systems.SQLiteStore, *groups.SQLiteStore, *sql.DB) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "creds.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	grpStore, err := groups.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("groups.NewSQLiteStore: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return store, sysStore, grpStore, db
}

func testVault(t *testing.T, seed byte) *secrets.Vault {
	t.Helper()
	k := make([]byte, secrets.KeySize)
	for i := range k {
		k[i] = seed + byte(i)
	}
	v, err := secrets.NewVaultFromKey(k)
	if err != nil {
		t.Fatalf("NewVaultFromKey: %v", err)
	}
	return v
}

func TestNewSQLiteStoreIdempotent(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "creds.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	// The credentials migration depends on hosts + system_groups
	// existing (cascade triggers reference both). Init them first,
	// matching production order in cmd/server/main.go.
	if _, err := systems.NewSQLiteStore(db); err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	if _, err := groups.NewSQLiteStore(db); err != nil {
		t.Fatalf("groups.NewSQLiteStore: %v", err)
	}
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("first NewSQLiteStore: %v", err)
	}
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("second NewSQLiteStore (idempotency): %v", err)
	}
}

func TestUpsertInsertThenUpdate(t *testing.T) {
	store := newStore(t)
	v := testVault(t, 7)
	sealed, err := SealWith(v, []byte("PRIVATE-KEY-1"))
	if err != nil {
		t.Fatalf("SealWith: %v", err)
	}

	first, err := store.Upsert(Slot{
		ScopeKind:   ScopeGlobal,
		AnsibleUser: "ansible",
		PublicKey:   "ssh-ed25519 AAAA1",
		PrivateKey:  sealed,
		Origin:      OriginSWGenerated,
	})
	if err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	if first.ID == "" {
		t.Error("first.ID is empty")
	}
	if first.CreatedAt.IsZero() || first.UpdatedAt.IsZero() {
		t.Error("created_at / updated_at not set on insert")
	}
	if !first.CreatedAt.Equal(first.UpdatedAt) {
		t.Errorf("on insert, created_at (%v) != updated_at (%v)", first.CreatedAt, first.UpdatedAt)
	}

	// Wait a hair, then upsert again. The row's id and created_at
	// must be preserved; updated_at must advance.
	time.Sleep(2 * time.Millisecond)
	sealed2, _ := SealWith(v, []byte("PRIVATE-KEY-2"))
	second, err := store.Upsert(Slot{
		ScopeKind:   ScopeGlobal,
		AnsibleUser: "deploy",
		PublicKey:   "ssh-ed25519 AAAA2",
		PrivateKey:  sealed2,
		Origin:      OriginUserSupplied,
	})
	if err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("id changed on update: %q -> %q", first.ID, second.ID)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("created_at changed on update: %v -> %v", first.CreatedAt, second.CreatedAt)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) {
		t.Errorf("updated_at did not advance: %v -> %v", first.UpdatedAt, second.UpdatedAt)
	}
	if second.AnsibleUser != "deploy" {
		t.Errorf("ansible_user = %q, want deploy", second.AnsibleUser)
	}
	if second.Origin != OriginUserSupplied {
		t.Errorf("origin = %q, want user_supplied", second.Origin)
	}
}

func TestUpsertScopeIsolation(t *testing.T) {
	store := newStore(t)
	v := testVault(t, 9)
	sealed, _ := SealWith(v, []byte("ROOT"))

	// Three rows at three different scopes — they must not collide.
	scopes := []Slot{
		{ScopeKind: ScopeGlobal, AnsibleUser: "global-user"},
		{ScopeKind: ScopeGroup, ScopeID: "group-A", AnsibleUser: "group-user"},
		{ScopeKind: ScopeSystem, ScopeID: "host-1", AnsibleUser: "system-user"},
	}
	for i := range scopes {
		// Give the second and third rows a sealed key too; tests
		// that we don't accidentally key the unique index on
		// scope_id alone.
		scopes[i].PublicKey = "ssh-ed25519 AAAA"
		scopes[i].PrivateKey = sealed
		scopes[i].Origin = OriginSWGenerated
		if _, err := store.Upsert(scopes[i]); err != nil {
			t.Fatalf("Upsert %q/%q: %v", scopes[i].ScopeKind, scopes[i].ScopeID, err)
		}
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("List returned %d rows, want 3", len(list))
	}
	// List is ordered global → group → system.
	wantOrder := []ScopeKind{ScopeGlobal, ScopeGroup, ScopeSystem}
	for i, got := range list {
		if got.ScopeKind != wantOrder[i] {
			t.Errorf("List[%d].ScopeKind = %q, want %q", i, got.ScopeKind, wantOrder[i])
		}
	}

	// A second global row must be treated as an update, not a new
	// row — the UNIQUE index on (scope_kind, COALESCE(scope_id,''))
	// makes "no scope_id" collide.
	again, err := store.Upsert(Slot{
		ScopeKind:   ScopeGlobal,
		AnsibleUser: "global-user-changed",
	})
	if err != nil {
		t.Fatalf("Upsert second global: %v", err)
	}
	if again.ID != list[0].ID {
		t.Errorf("second global got new id %q (orig %q)", again.ID, list[0].ID)
	}
}

func TestGetByScopeNotFound(t *testing.T) {
	store := newStore(t)
	if _, err := store.GetByScope(ScopeGroup, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing scope: err = %v, want ErrNotFound", err)
	}
}

func TestGetByScopeInvalidKind(t *testing.T) {
	store := newStore(t)
	if _, err := store.GetByScope(ScopeKind("bogus"), ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid kind: err = %v, want ErrInvalid", err)
	}
}

func TestDelete(t *testing.T) {
	store := newStore(t)
	if _, err := store.Upsert(Slot{
		ScopeKind:   ScopeGroup,
		ScopeID:     "g-1",
		AnsibleUser: "u",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := store.Delete(ScopeGroup, "g-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Delete(ScopeGroup, "g-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete: err = %v, want ErrNotFound", err)
	}
}

func TestDeleteInvalidKind(t *testing.T) {
	store := newStore(t)
	if err := store.Delete(ScopeKind("nope"), ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid kind: err = %v, want ErrInvalid", err)
	}
}

func TestSealedRoundTrip(t *testing.T) {
	store := newStore(t)
	v := testVault(t, 42)
	priv := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----")
	sealed, err := SealWith(v, priv)
	if err != nil {
		t.Fatalf("SealWith: %v", err)
	}
	if _, err := store.Upsert(Slot{
		ScopeKind:   ScopeSystem,
		ScopeID:     "h-1",
		AnsibleUser: "ansible",
		PublicKey:   "ssh-ed25519 AAAA",
		PrivateKey:  sealed,
		Origin:      OriginUserSupplied,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, err := store.GetByScope(ScopeSystem, "h-1")
	if err != nil {
		t.Fatalf("GetByScope: %v", err)
	}
	plain, err := OpenWith(v, got.PrivateKey)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	if string(plain) != string(priv) {
		t.Errorf("roundtrip plaintext mismatch:\ngot  %q\nwant %q", plain, priv)
	}
}

func TestCascadeDeleteFromHosts(t *testing.T) {
	store, sysStore, _, _ := newStoreWithSiblings(t)
	sys, err := sysStore.Create(systems.SystemInput{Name: "host-c", Hostname: "host-c.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	if _, err := store.Upsert(Slot{
		ScopeKind:   ScopeSystem,
		ScopeID:     sys.ID,
		AnsibleUser: "ansible",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// Seed a global slot too to prove the trigger only wipes
	// system-scoped rows for the deleted host.
	if _, err := store.Upsert(Slot{
		ScopeKind:   ScopeGlobal,
		AnsibleUser: "g",
	}); err != nil {
		t.Fatalf("Upsert global: %v", err)
	}
	if err := sysStore.Delete(sys.ID); err != nil {
		t.Fatalf("systems.Delete: %v", err)
	}
	if _, err := store.GetByScope(ScopeSystem, sys.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("system slot survived host delete: err = %v", err)
	}
	if _, err := store.GetByScope(ScopeGlobal, ""); err != nil {
		t.Errorf("global slot was wiped by host delete (should not have been): %v", err)
	}
}

func TestCascadeDeleteFromGroups(t *testing.T) {
	store, _, grpStore, _ := newStoreWithSiblings(t)
	g, err := grpStore.Create(groups.GroupInput{Name: "g-c"})
	if err != nil {
		t.Fatalf("groups.Create: %v", err)
	}
	if _, err := store.Upsert(Slot{
		ScopeKind:   ScopeGroup,
		ScopeID:     g.ID,
		AnsibleUser: "ansible",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := grpStore.Delete(g.ID); err != nil {
		t.Fatalf("groups.Delete: %v", err)
	}
	if _, err := store.GetByScope(ScopeGroup, g.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("group slot survived group delete: err = %v", err)
	}
}

func TestCascadeLeavesOtherScopesAlone(t *testing.T) {
	// Two systems, two slots. Deleting one system must leave the
	// other's slot intact — the trigger has to filter by OLD.id,
	// not blindly wipe scope_kind='system'.
	store, sysStore, _, _ := newStoreWithSiblings(t)
	a, err := sysStore.Create(systems.SystemInput{Name: "a", Hostname: "a.example"})
	if err != nil {
		t.Fatalf("systems.Create a: %v", err)
	}
	b, err := sysStore.Create(systems.SystemInput{Name: "b", Hostname: "b.example"})
	if err != nil {
		t.Fatalf("systems.Create b: %v", err)
	}
	for _, id := range []string{a.ID, b.ID} {
		if _, err := store.Upsert(Slot{
			ScopeKind:   ScopeSystem,
			ScopeID:     id,
			AnsibleUser: "u",
		}); err != nil {
			t.Fatalf("Upsert %s: %v", id, err)
		}
	}
	if err := sysStore.Delete(a.ID); err != nil {
		t.Fatalf("systems.Delete a: %v", err)
	}
	if _, err := store.GetByScope(ScopeSystem, b.ID); err != nil {
		t.Errorf("b's slot was wiped along with a: %v", err)
	}
}

func TestUpsertValidationRejects(t *testing.T) {
	store := newStore(t)
	tests := []struct {
		name string
		slot Slot
	}{
		{"empty scope kind", Slot{}},
		{"global with scope_id", Slot{ScopeKind: ScopeGlobal, ScopeID: "x", AnsibleUser: "u"}},
		{"group without scope_id", Slot{ScopeKind: ScopeGroup, AnsibleUser: "u"}},
		{"system without scope_id", Slot{ScopeKind: ScopeSystem, AnsibleUser: "u"}},
		{"neither user nor key", Slot{ScopeKind: ScopeGlobal}},
		{"public without private", Slot{
			ScopeKind: ScopeGlobal, PublicKey: "ssh-ed25519 AAAA",
			Origin: OriginSWGenerated,
		}},
		{"key without origin", Slot{
			ScopeKind:  ScopeGlobal,
			PublicKey:  "ssh-ed25519 AAAA",
			PrivateKey: Sealed{Ciphertext: []byte{1}, Nonce: []byte{1}, Version: 1},
		}},
		{"origin without key", Slot{
			ScopeKind:   ScopeGlobal,
			AnsibleUser: "u",
			Origin:      OriginSWGenerated,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := store.Upsert(tt.slot); !errors.Is(err, ErrInvalid) {
				t.Errorf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestStoreClosedDBSurfacesErrors(t *testing.T) {
	store, _, _, db := newStoreWithSiblings(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	type call struct {
		name string
		fn   func() error
	}
	calls := []call{
		{"GetByScope", func() error { _, err := store.GetByScope(ScopeGlobal, ""); return err }},
		{"List", func() error { _, err := store.List(); return err }},
		{"Upsert", func() error {
			_, err := store.Upsert(Slot{ScopeKind: ScopeGlobal, AnsibleUser: "u"})
			return err
		}},
		{"Delete", func() error { return store.Delete(ScopeGlobal, "") }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(); err == nil {
				t.Errorf("%s on closed DB returned nil error", c.name)
			}
		})
	}
}
