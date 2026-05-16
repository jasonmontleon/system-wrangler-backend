// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/systems"
)

func newStore(t *testing.T) *SQLiteStore {
	t.Helper()
	store, _, _, _ := newStoreWithSiblings(t)
	return store
}

// newStoreWithSiblings opens a fresh temp DB and initialises every
// store the updaters migration depends on. Triggers attach to hosts,
// so systems must exist before updaters; groups parallels the
// credentials test fixture for symmetry.
func newStoreWithSiblings(t *testing.T) (*SQLiteStore, *systems.SQLiteStore, *groups.SQLiteStore, *sql.DB) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "updaters.db")
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

func TestNewSQLiteStoreIdempotent(t *testing.T) {
	_, _, _, db := newStoreWithSiblings(t)
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("second NewSQLiteStore: %v", err)
	}
}

func sampleDef(id string) Definition {
	return Definition{
		ID:            id,
		Source:        SourceCustom,
		DisplayName:   "Test " + id,
		Description:   "sample",
		DetectBinary:  "echo",
		CheckPlaybook: []byte("- hosts: all\n  tasks: []\n"),
		ApplyPlaybook: []byte("- hosts: all\n  tasks: []\n"),
		CreatedBy:     "user-1",
	}
}

func TestCreateCustomRoundTrip(t *testing.T) {
	store := newStore(t)
	d := sampleDef("custom.alpha")
	created, err := store.CreateCustom(d)
	if err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("timestamps not stamped: %+v", created)
	}
	if !created.CreatedAt.Equal(created.UpdatedAt) {
		t.Errorf("on insert created != updated: %v vs %v", created.CreatedAt, created.UpdatedAt)
	}
	got, err := store.GetCustom("custom.alpha")
	if err != nil {
		t.Fatalf("GetCustom: %v", err)
	}
	if got.DisplayName != "Test custom.alpha" {
		t.Errorf("display_name lost in round trip: %q", got.DisplayName)
	}
	if got.Source != SourceCustom {
		t.Errorf("source = %q, want custom", got.Source)
	}
}

func TestCreateCustomRejectsBuiltinPrefix(t *testing.T) {
	store := newStore(t)
	_, err := store.CreateCustom(sampleDef("builtin.bogus"))
	if !errors.Is(err, ErrReservedID) {
		t.Fatalf("err = %v, want ErrReservedID", err)
	}
}

func TestCreateCustomDuplicate(t *testing.T) {
	store := newStore(t)
	if _, err := store.CreateCustom(sampleDef("custom.dup")); err != nil {
		t.Fatalf("first CreateCustom: %v", err)
	}
	if _, err := store.CreateCustom(sampleDef("custom.dup")); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err = %v, want ErrDuplicate", err)
	}
}

func TestUpdateCustomAdvancesUpdatedAt(t *testing.T) {
	store := newStore(t)
	first, err := store.CreateCustom(sampleDef("custom.alpha"))
	if err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	d := sampleDef("custom.alpha")
	d.DisplayName = "renamed"
	got, err := store.UpdateCustom(d)
	if err != nil {
		t.Fatalf("UpdateCustom: %v", err)
	}
	if !got.UpdatedAt.After(first.UpdatedAt) {
		t.Errorf("updated_at did not advance: %v -> %v", first.UpdatedAt, got.UpdatedAt)
	}
	if !got.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("created_at changed: %v -> %v", first.CreatedAt, got.CreatedAt)
	}
	if got.CreatedBy != "user-1" {
		t.Errorf("created_by lost across update: %q", got.CreatedBy)
	}
}

func TestUpdateCustomNotFound(t *testing.T) {
	store := newStore(t)
	if _, err := store.UpdateCustom(sampleDef("custom.missing")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleteCustomSoftDelete(t *testing.T) {
	store := newStore(t)
	if _, err := store.CreateCustom(sampleDef("custom.beta")); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	if err := store.DeleteCustom("custom.beta", time.Now()); err != nil {
		t.Fatalf("DeleteCustom: %v", err)
	}
	// GetCustom must still resolve the row (for audit/history).
	d, err := store.GetCustom("custom.beta")
	if err != nil {
		t.Fatalf("GetCustom after soft delete: %v", err)
	}
	if !d.IsDeleted() {
		t.Errorf("deleted_at not set on soft-deleted row")
	}
	// ListCustom must skip it.
	list, err := store.ListCustom()
	if err != nil {
		t.Fatalf("ListCustom: %v", err)
	}
	for _, row := range list {
		if row.ID == "custom.beta" {
			t.Errorf("ListCustom returned soft-deleted row %q", row.ID)
		}
	}
	// Second delete is a no-op (row already tombstoned).
	if err := store.DeleteCustom("custom.beta", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteCustom: err = %v, want ErrNotFound", err)
	}
}

func TestUpdateCustomRejectsDeleted(t *testing.T) {
	store := newStore(t)
	if _, err := store.CreateCustom(sampleDef("custom.gamma")); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	if err := store.DeleteCustom("custom.gamma", time.Now()); err != nil {
		t.Fatalf("DeleteCustom: %v", err)
	}
	if _, err := store.UpdateCustom(sampleDef("custom.gamma")); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestUpsertAvailability(t *testing.T) {
	store := newStore(t)
	now := time.Now()
	if err := store.UpsertAvailability("sys-1", "builtin.dnf", now); err != nil {
		t.Fatalf("first Upsert: %v", err)
	}
	later := now.Add(time.Minute)
	if err := store.UpsertAvailability("sys-1", "builtin.dnf", later); err != nil {
		t.Fatalf("second Upsert: %v", err)
	}
	list, err := store.AvailabilityFor("sys-1")
	if err != nil {
		t.Fatalf("AvailabilityFor: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1 (upsert must dedupe)", len(list))
	}
	if list[0].LastSeenAt == nil || !list[0].LastSeenAt.Equal(later.UTC()) {
		t.Errorf("last_seen_at = %v, want %v", list[0].LastSeenAt, later.UTC())
	}
}

func TestRemoveAvailability(t *testing.T) {
	store := newStore(t)
	if err := store.UpsertAvailability("sys-1", "builtin.dnf", time.Now()); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := store.RemoveAvailability("sys-1", "builtin.dnf"); err != nil {
		t.Fatalf("RemoveAvailability: %v", err)
	}
	list, _ := store.AvailabilityFor("sys-1")
	if len(list) != 0 {
		t.Errorf("len = %d, want 0", len(list))
	}
}

func TestInsertAndFinishRun(t *testing.T) {
	store := newStore(t)
	now := time.Now().UTC()
	r := Run{
		ID:          "run-1",
		SystemID:    "sys-1",
		UpdaterID:   "builtin.dnf",
		Kind:        RunKindCheck,
		StartedAt:   now,
		ActorID:     "user-1",
		PlaybookSHA: "abc123",
	}
	if err := store.InsertRun(r); err != nil {
		t.Fatalf("InsertRun: %v", err)
	}
	if err := store.FinishRun("run-1", now.Add(2*time.Second), 0, 7, "ok\n"); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	list, err := store.ListRuns("sys-1", 10)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1", len(list))
	}
	got := list[0]
	if got.ExitCode == nil || *got.ExitCode != 0 {
		t.Errorf("exit_code = %v, want 0", got.ExitCode)
	}
	if got.LogTail != "ok\n" {
		t.Errorf("log_tail = %q, want %q", got.LogTail, "ok\n")
	}
	if got.FinishedAt == nil {
		t.Errorf("finished_at was not set")
	}
}

func TestFinishRunTruncatesLogTail(t *testing.T) {
	store := newStore(t)
	now := time.Now().UTC()
	if err := store.InsertRun(Run{
		ID:        "run-2",
		SystemID:  "sys-2",
		UpdaterID: "builtin.dnf",
		Kind:      RunKindApply,
		StartedAt: now,
	}); err != nil {
		t.Fatalf("InsertRun: %v", err)
	}
	big := strings.Repeat("X", MaxLogTailBytes+1024)
	if err := store.FinishRun("run-2", now.Add(time.Second), 1, 0, big); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	list, _ := store.ListRuns("sys-2", 10)
	if len(list) != 1 {
		t.Fatalf("len = %d", len(list))
	}
	if len(list[0].LogTail) != MaxLogTailBytes {
		t.Errorf("log_tail len = %d, want %d", len(list[0].LogTail), MaxLogTailBytes)
	}
}

func TestAcquireLockSerializes(t *testing.T) {
	store := newStore(t)
	now := time.Now().UTC()
	if err := store.AcquireLock("sys-3", "run-A", now); err != nil {
		t.Fatalf("first AcquireLock: %v", err)
	}
	if err := store.AcquireLock("sys-3", "run-B", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	holder, err := store.ConflictingRun("sys-3")
	if err != nil {
		t.Fatalf("ConflictingRun: %v", err)
	}
	if holder != "run-A" {
		t.Errorf("ConflictingRun = %q, want run-A", holder)
	}
	// Release the original and the second acquire succeeds.
	if err := store.ReleaseLock("sys-3", "run-A"); err != nil {
		t.Fatalf("ReleaseLock: %v", err)
	}
	if err := store.AcquireLock("sys-3", "run-B", now); err != nil {
		t.Fatalf("second AcquireLock after release: %v", err)
	}
}

func TestReleaseLockIdempotent(t *testing.T) {
	store := newStore(t)
	if err := store.ReleaseLock("sys-never", "run-never"); err != nil {
		t.Errorf("ReleaseLock on missing row: %v", err)
	}
}

func TestCascadeWipesOnHostDelete(t *testing.T) {
	store, sysStore, _, _ := newStoreWithSiblings(t)
	sys, err := sysStore.Create(systems.SystemInput{Name: "doomed", Hostname: "doom.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	now := time.Now().UTC()
	if err := store.UpsertAvailability(sys.ID, "builtin.dnf", now); err != nil {
		t.Fatalf("UpsertAvailability: %v", err)
	}
	if err := store.AcquireLock(sys.ID, "run-x", now); err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if err := store.InsertRun(Run{
		ID:        "run-x",
		SystemID:  sys.ID,
		UpdaterID: "builtin.dnf",
		Kind:      RunKindApply,
		StartedAt: now,
	}); err != nil {
		t.Fatalf("InsertRun: %v", err)
	}
	if err := sysStore.Delete(sys.ID); err != nil {
		t.Fatalf("systems.Delete: %v", err)
	}
	if list, _ := store.AvailabilityFor(sys.ID); len(list) != 0 {
		t.Errorf("availability survived host delete: %v", list)
	}
	if list, _ := store.ListRuns(sys.ID, 10); len(list) != 0 {
		t.Errorf("runs survived host delete: %v", list)
	}
	if holder, _ := store.ConflictingRun(sys.ID); holder != "" {
		t.Errorf("lock survived host delete: %q", holder)
	}
}
