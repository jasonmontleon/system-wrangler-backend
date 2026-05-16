// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"path/filepath"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/systems"
)

// brokenStore returns a SQLiteStore whose underlying *sql.DB has
// been closed. Every Exec / Query against it errors at the driver
// level, so this fixture lets us exercise the fmt.Errorf wraps the
// happy-path tests don't reach.
func brokenStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "broken.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	if _, err := systems.NewSQLiteStore(db); err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	if _, err := groups.NewSQLiteStore(db); err != nil {
		t.Fatalf("groups.NewSQLiteStore: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	_ = db.Close()
	return store
}

func TestStoreErrorWrapping(t *testing.T) {
	store := brokenStore(t)
	now := time.Now()

	if _, err := store.ListCustom(); err == nil {
		t.Error("ListCustom: expected error against closed db")
	}
	if _, err := store.CreateCustom(sampleDef("custom.broken")); err == nil {
		t.Error("CreateCustom: expected error")
	}
	if err := store.DeleteCustom("custom.broken", now); err == nil {
		t.Error("DeleteCustom: expected error")
	}
	if err := store.UpsertAvailability("sys", "builtin.dnf", now); err == nil {
		t.Error("UpsertAvailability: expected error")
	}
	if err := store.RemoveAvailability("sys", "builtin.dnf"); err == nil {
		t.Error("RemoveAvailability: expected error")
	}
	if _, err := store.AvailabilityFor("sys"); err == nil {
		t.Error("AvailabilityFor: expected error")
	}
	if err := store.InsertRun(Run{
		ID:        "run-x",
		SystemID:  "sys",
		UpdaterID: "builtin.dnf",
		Kind:      RunKindApply,
		StartedAt: now,
	}); err == nil {
		t.Error("InsertRun: expected error")
	}
	if err := store.FinishRun("run-x", now, 0, 0, ""); err == nil {
		t.Error("FinishRun: expected error")
	}
	if _, err := store.ListRuns("sys", 10); err == nil {
		t.Error("ListRuns: expected error")
	}
	if err := store.AcquireLock("sys", "run", now); err == nil {
		t.Error("AcquireLock: expected error")
	}
	if err := store.ReleaseLock("sys", "run"); err == nil {
		t.Error("ReleaseLock: expected error")
	}
	if _, err := store.ConflictingRun("sys"); err == nil {
		t.Error("ConflictingRun: expected error")
	}
	if _, err := store.SystemStatsAll(); err == nil {
		t.Error("SystemStatsAll: expected error against closed db")
	}
}

func TestNewSQLiteStoreOnClosedDB(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "x.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	_ = db.Close()
	if _, err := NewSQLiteStore(db); err == nil {
		t.Error("NewSQLiteStore on closed DB: expected error")
	}
}

func TestRegistryAllErrorPropagates(t *testing.T) {
	store := brokenStore(t)
	reg := NewRegistry(store)
	if _, err := reg.All(); err == nil {
		t.Error("All: expected error from broken store")
	}
}
