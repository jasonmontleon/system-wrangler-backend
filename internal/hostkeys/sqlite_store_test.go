// SPDX-License-Identifier: Apache-2.0

package hostkeys

import (
	"errors"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/systems"
)

func newStore(t *testing.T) (*SQLiteStore, *systems.SQLiteStore) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "hk.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("hostkeys.NewSQLiteStore: %v", err)
	}
	return store, sysStore
}

func seedSystem(t *testing.T, s *systems.SQLiteStore, name string) string {
	t.Helper()
	sys, err := s.Create(systems.SystemInput{Name: name, Hostname: name + ".example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	return sys.ID
}

func TestNewSQLiteStoreIdempotent(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "hk-idem.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("first NewSQLiteStore: %v", err)
	}
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("second NewSQLiteStore: %v", err)
	}
}

func TestRecordPendingInsertsThenDedupes(t *testing.T) {
	store, sysStore := newStore(t)
	sysID := seedSystem(t, sysStore, "host-1")

	first, err := store.RecordPending(sysID, "ssh-ed25519", "AAAA...", "SHA256:abc")
	if err != nil {
		t.Fatalf("first RecordPending: %v", err)
	}
	if first.State != StatePending {
		t.Errorf("state = %q, want pending", first.State)
	}

	// Same fingerprint → no-op, first_seen_at preserved.
	again, err := store.RecordPending(sysID, "ssh-ed25519", "AAAA...", "SHA256:abc")
	if err != nil {
		t.Fatalf("second RecordPending: %v", err)
	}
	if again.ID != first.ID || !again.FirstSeenAt.Equal(first.FirstSeenAt) {
		t.Errorf("dedupe failed: ID changed %q→%q or first_seen_at moved", first.ID, again.ID)
	}
}

func TestRecordPendingOverwritesOnFingerprintChange(t *testing.T) {
	store, sysStore := newStore(t)
	sysID := seedSystem(t, sysStore, "host-2")
	first, _ := store.RecordPending(sysID, "ssh-ed25519", "AAAA...", "SHA256:old")
	second, err := store.RecordPending(sysID, "ssh-ed25519", "BBBB...", "SHA256:new")
	if err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("ID changed on overwrite: %q→%q (should reuse the row)", first.ID, second.ID)
	}
	if second.Fingerprint != "SHA256:new" || second.PublicKey != "BBBB..." {
		t.Errorf("fields not updated: fp=%q pub=%q", second.Fingerprint, second.PublicKey)
	}
}

func TestRecordPendingValidatesInput(t *testing.T) {
	store, _ := newStore(t)
	cases := []struct {
		name string
		args [4]string
	}{
		{"empty system", [4]string{"", "ssh-ed25519", "pub", "fp"}},
		{"empty algo", [4]string{"s", "", "pub", "fp"}},
		{"empty pub", [4]string{"s", "ssh-ed25519", "", "fp"}},
		{"empty fp", [4]string{"s", "ssh-ed25519", "pub", ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := store.RecordPending(c.args[0], c.args[1], c.args[2], c.args[3]); !errors.Is(err, ErrInvalid) {
				t.Errorf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestAcceptPromotesPending(t *testing.T) {
	store, sysStore := newStore(t)
	sysID := seedSystem(t, sysStore, "host-3")
	if _, err := store.RecordPending(sysID, "ssh-ed25519", "AAAA...", "SHA256:abc"); err != nil {
		t.Fatalf("RecordPending: %v", err)
	}

	hk, replaced, err := store.Accept(sysID, "ssh-ed25519", "SHA256:abc", "user-1")
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if replaced {
		t.Error("first accept reported replaced=true")
	}
	if hk.State != StateAccepted {
		t.Errorf("state = %q, want accepted", hk.State)
	}
	if hk.AcceptedBy != "user-1" {
		t.Errorf("accepted_by = %q, want user-1", hk.AcceptedBy)
	}
	if hk.AcceptedAt == nil {
		t.Error("accepted_at is nil after accept")
	}
}

func TestAcceptReplacesPriorAccepted(t *testing.T) {
	store, sysStore := newStore(t)
	sysID := seedSystem(t, sysStore, "host-4")
	// First key, accepted.
	if _, err := store.RecordPending(sysID, "ssh-ed25519", "AAAA...", "SHA256:old"); err != nil {
		t.Fatalf("RecordPending old: %v", err)
	}
	if _, _, err := store.Accept(sysID, "ssh-ed25519", "SHA256:old", "user-1"); err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	// New key arrives (rotation), pending.
	if _, err := store.RecordPending(sysID, "ssh-ed25519", "BBBB...", "SHA256:new"); err != nil {
		t.Fatalf("RecordPending new: %v", err)
	}
	hk, replaced, err := store.Accept(sysID, "ssh-ed25519", "SHA256:new", "user-2")
	if err != nil {
		t.Fatalf("Accept replace: %v", err)
	}
	if !replaced {
		t.Error("replace accept reported replaced=false")
	}
	if hk.Fingerprint != "SHA256:new" {
		t.Errorf("fingerprint = %q, want SHA256:new", hk.Fingerprint)
	}
	// And only one accepted row exists for the algorithm.
	all, err := store.AcceptedFor(sysID)
	if err != nil {
		t.Fatalf("AcceptedFor: %v", err)
	}
	count := 0
	for _, k := range all {
		if k.Algorithm == "ssh-ed25519" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("accepted ed25519 rows = %d, want 1", count)
	}
}

func TestAcceptStaleFingerprint(t *testing.T) {
	store, sysStore := newStore(t)
	sysID := seedSystem(t, sysStore, "host-5")
	if _, err := store.RecordPending(sysID, "ssh-ed25519", "AAAA...", "SHA256:current"); err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	if _, _, err := store.Accept(sysID, "ssh-ed25519", "SHA256:stale", "u"); !errors.Is(err, ErrFingerprintStale) {
		t.Errorf("err = %v, want ErrFingerprintStale", err)
	}
}

func TestAcceptNoPending(t *testing.T) {
	store, sysStore := newStore(t)
	sysID := seedSystem(t, sysStore, "host-6")
	if _, _, err := store.Accept(sysID, "ssh-ed25519", "fp", "u"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestAcceptValidates(t *testing.T) {
	store, _ := newStore(t)
	if _, _, err := store.Accept("", "alg", "fp", "u"); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty system: err = %v", err)
	}
}

func TestListOrdersAcceptedFirst(t *testing.T) {
	store, sysStore := newStore(t)
	sysID := seedSystem(t, sysStore, "host-7")
	// One accepted, one pending (different algos).
	if _, err := store.RecordPending(sysID, "ssh-rsa", "RRR...", "SHA256:rsa"); err != nil {
		t.Fatalf("RecordPending rsa: %v", err)
	}
	if _, _, err := store.Accept(sysID, "ssh-rsa", "SHA256:rsa", "u"); err != nil {
		t.Fatalf("Accept rsa: %v", err)
	}
	if _, err := store.RecordPending(sysID, "ssh-ed25519", "EEE...", "SHA256:ed"); err != nil {
		t.Fatalf("RecordPending ed25519: %v", err)
	}
	list, err := store.List(sysID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].State != StateAccepted || list[1].State != StatePending {
		t.Errorf("ordering wrong: %q then %q", list[0].State, list[1].State)
	}
}

func TestDeleteRow(t *testing.T) {
	store, sysStore := newStore(t)
	sysID := seedSystem(t, sysStore, "host-8")
	rec, err := store.RecordPending(sysID, "ssh-ed25519", "EEE...", "SHA256:ed")
	if err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	if err := store.Delete(rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := store.Delete(rec.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete: err = %v, want ErrNotFound", err)
	}
}

func TestGetMissing(t *testing.T) {
	store, _ := newStore(t)
	if _, err := store.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestForeignKeyCascadeOnSystemDelete(t *testing.T) {
	store, sysStore := newStore(t)
	sysID := seedSystem(t, sysStore, "host-9")
	if _, err := store.RecordPending(sysID, "ssh-ed25519", "EEE...", "SHA256:ed"); err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	if err := sysStore.Delete(sysID); err != nil {
		t.Fatalf("systems.Delete: %v", err)
	}
	list, err := store.List(sysID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected cascade-delete; got %d rows", len(list))
	}
}

func TestStateIsValid(t *testing.T) {
	for _, s := range []State{StatePending, StateAccepted} {
		if !s.IsValid() {
			t.Errorf("%q reported invalid", s)
		}
	}
	if State("bogus").IsValid() {
		t.Error("bogus reported valid")
	}
}
