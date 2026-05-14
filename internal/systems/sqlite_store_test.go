// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
)

// newTestSQLiteStore opens an SQLiteStore against a per-test file with the
// same deterministic NewID/Now overrides as newTestStore, so the assertions
// in this file mirror the MemStore tests.
func newTestSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "test.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	var counter atomic.Int64
	s.NewID = func() string {
		return fmt.Sprintf("id-%d", counter.Add(1))
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var tick atomic.Int64
	s.Now = func() time.Time {
		return base.Add(time.Duration(tick.Add(1)) * time.Second)
	}
	return s
}

func TestSQLiteOpenInvalidDSN(t *testing.T) {
	// A path under a nonexistent directory cannot be created; SQLite returns
	// an error during the first PRAGMA exec.
	_, err := database.Open("file:/nonexistent-dir-xyzzy/never.db")
	if err == nil {
		t.Fatal("database.Open on bad path: want error, got nil")
	}
}

func TestSQLiteStoreCreateAndGet(t *testing.T) {
	s := newTestSQLiteStore(t)
	h, err := s.Create(SystemInput{Name: "  host1 ", Hostname: " 10.0.0.1 "})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if h.ID != "id-1" {
		t.Errorf("ID = %q, want id-1", h.ID)
	}
	if h.Name != "host1" || h.Hostname != "10.0.0.1" {
		t.Errorf("trim failed: %+v", h)
	}
	if h.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
	if h.CreatedAt.Location() != time.UTC {
		t.Error("CreatedAt should be UTC")
	}
	if h.Status != StatusUnprobed {
		t.Errorf("Status = %q, want %q", h.Status, StatusUnprobed)
	}
	if h.LastSeen != nil {
		t.Errorf("LastSeen = %v, want nil", h.LastSeen)
	}

	got, err := s.Get(h.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != h.ID || got.Name != h.Name || got.Hostname != h.Hostname {
		t.Errorf("Get returned %+v, want %+v", got, h)
	}
	if !got.CreatedAt.Equal(h.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, h.CreatedAt)
	}
	if got.Status != h.Status {
		t.Errorf("Status = %q, want %q", got.Status, h.Status)
	}
}

func TestSQLiteStoreCreateInvalid(t *testing.T) {
	s := newTestSQLiteStore(t)
	_, err := s.Create(SystemInput{Name: "", Hostname: "1.2.3.4"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	systems, _ := s.List()
	if len(systems) != 0 {
		t.Errorf("invalid create should not persist; got %d systems", len(systems))
	}
}

func TestSQLiteStoreGetMissing(t *testing.T) {
	s := newTestSQLiteStore(t)
	if _, err := s.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestSQLiteStoreListOrdered(t *testing.T) {
	s := newTestSQLiteStore(t)
	for i := 0; i < 3; i++ {
		if _, err := s.Create(SystemInput{Name: "h" + strconv.Itoa(i), Hostname: "1.1.1.1"}); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	systems, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(systems) != 3 {
		t.Fatalf("len = %d, want 3", len(systems))
	}
	for i := 1; i < len(systems); i++ {
		if systems[i].CreatedAt.Before(systems[i-1].CreatedAt) {
			t.Errorf("systems not ordered by CreatedAt: %+v", systems)
		}
	}
}

func TestSQLiteStoreListEmpty(t *testing.T) {
	s := newTestSQLiteStore(t)
	systems, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(systems) != 0 {
		t.Errorf("len = %d, want 0", len(systems))
	}
	// Non-nil empty slice keeps JSON marshaling as `[]` not `null`.
	if systems == nil {
		t.Error("List on empty store returned nil; want non-nil empty slice")
	}
}

func TestSQLiteStoreDelete(t *testing.T) {
	s := newTestSQLiteStore(t)
	h, _ := s.Create(SystemInput{Name: "h", Hostname: "1.1.1.1"})
	if err := s.Delete(h.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(h.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete Get err = %v, want ErrNotFound", err)
	}
	if err := s.Delete(h.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete err = %v, want ErrNotFound", err)
	}
}

func TestSQLiteStoreUpdateProbe(t *testing.T) {
	s := newTestSQLiteStore(t)
	h, _ := s.Create(SystemInput{Name: "h", Hostname: "1.1.1.1"})
	probeAt := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	if err := s.UpdateProbe(h.ID, true, probeAt); err != nil {
		t.Fatalf("UpdateProbe ok: %v", err)
	}
	got, _ := s.Get(h.ID)
	if got.Status != StatusReachable {
		t.Errorf("Status = %q, want reachable", got.Status)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(probeAt) {
		t.Errorf("LastSeen = %v, want %v", got.LastSeen, probeAt)
	}

	// A failed probe sets Unreachable but preserves LastSeen.
	failAt := probeAt.Add(time.Minute)
	if err := s.UpdateProbe(h.ID, false, failAt); err != nil {
		t.Fatalf("UpdateProbe fail: %v", err)
	}
	got, _ = s.Get(h.ID)
	if got.Status != StatusUnreachable {
		t.Errorf("Status = %q, want unreachable", got.Status)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(probeAt) {
		t.Errorf("LastSeen = %v, want preserved %v", got.LastSeen, probeAt)
	}
}

func TestSQLiteStoreUpdateProbeMissing(t *testing.T) {
	s := newTestSQLiteStore(t)
	if err := s.UpdateProbe("nope", true, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// TestSQLiteStorePersistence verifies that data written through one
// *SQLiteStore is visible when the same DB file is reopened — guarding
// against any future change that accidentally moves state into process-local
// memory.
func TestSQLiteStorePersistence(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "persist.db")

	db1, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open #1: %v", err)
	}
	s1, err := NewSQLiteStore(db1)
	if err != nil {
		t.Fatalf("NewSQLiteStore #1: %v", err)
	}
	h, err := s1.Create(SystemInput{Name: "persisted", Hostname: "10.0.0.99"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := db1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db2, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open #2: %v", err)
	}
	defer func() { _ = db2.Close() }()
	s2, err := NewSQLiteStore(db2)
	if err != nil {
		t.Fatalf("NewSQLiteStore #2: %v", err)
	}

	got, err := s2.Get(h.ID)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.Name != "persisted" || got.Hostname != "10.0.0.99" {
		t.Errorf("after reopen got %+v", got)
	}
	if !got.CreatedAt.Equal(h.CreatedAt) {
		t.Errorf("CreatedAt drifted: %v vs %v", got.CreatedAt, h.CreatedAt)
	}
}

// TestSQLiteStoreConcurrent exercises MaxOpenConns=1 serialization under -race.
func TestSQLiteStoreConcurrent(t *testing.T) {
	s := newTestSQLiteStore(t)
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			if _, err := s.Create(SystemInput{Name: "h" + strconv.Itoa(i), Hostname: "1.1.1.1"}); err != nil {
				t.Errorf("Create: %v", err)
			}
			if _, err := s.List(); err != nil {
				t.Errorf("List: %v", err)
			}
		}(i)
	}
	wg.Wait()
	systems, _ := s.List()
	if len(systems) != n {
		t.Errorf("len = %d, want %d", len(systems), n)
	}
}

func TestSQLiteSetGroupRoundTrip(t *testing.T) {
	s := newTestSQLiteStore(t)
	h, _ := s.Create(SystemInput{Name: "h", Hostname: "1.1.1.1"})
	gid := "group-x"
	if err := s.SetGroup(h.ID, &gid); err != nil {
		t.Fatalf("SetGroup assign: %v", err)
	}
	got, _ := s.Get(h.ID)
	if got.GroupID == nil || *got.GroupID != gid {
		t.Errorf("GroupID = %v, want %q", got.GroupID, gid)
	}
	if err := s.SetGroup(h.ID, nil); err != nil {
		t.Fatalf("SetGroup clear: %v", err)
	}
	got, _ = s.Get(h.ID)
	if got.GroupID != nil {
		t.Errorf("after clear GroupID = %v, want nil", got.GroupID)
	}
}

func TestSQLiteSetGroupMissing(t *testing.T) {
	s := newTestSQLiteStore(t)
	gid := "group-x"
	if err := s.SetGroup("nope", &gid); !errors.Is(err, ErrNotFound) {
		t.Errorf("set err = %v, want ErrNotFound", err)
	}
	if err := s.SetGroup("nope", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("clear err = %v, want ErrNotFound", err)
	}
}

func TestSQLiteClearGroup(t *testing.T) {
	s := newTestSQLiteStore(t)
	a, _ := s.Create(SystemInput{Name: "a", Hostname: "1.1.1.1"})
	b, _ := s.Create(SystemInput{Name: "b", Hostname: "1.1.1.2"})
	gid := "shared"
	if err := s.SetGroup(a.ID, &gid); err != nil {
		t.Fatalf("SetGroup a: %v", err)
	}
	if err := s.SetGroup(b.ID, &gid); err != nil {
		t.Fatalf("SetGroup b: %v", err)
	}
	if err := s.ClearGroup(gid); err != nil {
		t.Fatalf("ClearGroup: %v", err)
	}
	gotA, _ := s.Get(a.ID)
	gotB, _ := s.Get(b.ID)
	if gotA.GroupID != nil || gotB.GroupID != nil {
		t.Errorf("ClearGroup didn't clear: a=%v b=%v", gotA.GroupID, gotB.GroupID)
	}
}

func TestSQLiteAddGroupIDColumnIdempotent(t *testing.T) {
	// Re-running NewSQLiteStore on the same DB must be a no-op — the
	// idempotent ALTER path is what supports upgrades over existing data.
	s := newTestSQLiteStore(t)
	h, _ := s.Create(SystemInput{Name: "h", Hostname: "1.1.1.1"})
	if _, err := NewSQLiteStore(s.db); err != nil {
		t.Fatalf("second NewSQLiteStore: %v", err)
	}
	if _, err := s.Get(h.ID); err != nil {
		t.Errorf("Get after second init: %v", err)
	}
}

// TestSQLiteMigratesLegacySchema reproduces the upgrade path from a
// database created before group_id existed. CREATE TABLE IF NOT EXISTS
// will not retrofit the column; the migration must add it and only then
// create the supporting index. This guards against a regression where
// the index was created in the same Exec batch as the table and failed
// on existing deployments.
func TestSQLiteMigratesLegacySchema(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "legacy.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Plant the pre-group_id schema by hand.
	if _, err := db.Exec(`
		CREATE TABLE hosts (
		    id          TEXT PRIMARY KEY,
		    name        TEXT NOT NULL,
		    hostname    TEXT NOT NULL,
		    created_at  INTEGER NOT NULL,
		    status      TEXT NOT NULL,
		    last_seen   INTEGER
		) STRICT;
		CREATE INDEX hosts_created_at ON hosts(created_at, id);
	`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}

	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore on legacy db: %v", err)
	}
	// A round-trip after migration must work and round-trip group_id.
	h, err := store.Create(SystemInput{Name: "h", Hostname: "1.1.1.1"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	gid := "g-1"
	if err := store.SetGroup(h.ID, &gid); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}
	got, _ := store.Get(h.ID)
	if got.GroupID == nil || *got.GroupID != gid {
		t.Errorf("GroupID = %v, want %q", got.GroupID, gid)
	}
}
