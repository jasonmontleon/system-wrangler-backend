// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/database"
)

// openLegacyDB opens a fresh DB at dsn and hand-creates an
// updater_runs table WITHOUT the affected_count column — the shape
// a System Wrangler version from before this column existed would
// have produced. Used by the migration test below.
func openLegacyDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE updater_runs (
		id TEXT PRIMARY KEY,
		system_id TEXT NOT NULL,
		updater_id TEXT NOT NULL DEFAULT '',
		kind TEXT NOT NULL,
		started_at INTEGER NOT NULL
	) STRICT`); err != nil {
		t.Fatalf("legacy schema: %v", err)
	}
	return db
}

func TestSystemStatsAllEmpty(t *testing.T) {
	store := newStore(t)
	got, err := store.SystemStatsAll()
	if err != nil {
		t.Fatalf("SystemStatsAll: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0 (no runs yet)", len(got))
	}
}

func TestSystemStatsAllAggregatesLatestCheck(t *testing.T) {
	store := newStore(t)
	now := time.Now().UTC()

	// Two check runs against the same updater on sys-1: the LATER
	// one wins the per-updater pending count.
	if err := store.InsertRun(Run{
		ID: "r-old", SystemID: "sys-1", UpdaterID: "builtin.dnf",
		Kind: RunKindCheck, StartedAt: now.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("insert old: %v", err)
	}
	if err := store.FinishRun("r-old", now.Add(-2*time.Hour).Add(time.Minute), 0, 99, ""); err != nil {
		t.Fatalf("finish old: %v", err)
	}
	if err := store.InsertRun(Run{
		ID: "r-new", SystemID: "sys-1", UpdaterID: "builtin.dnf",
		Kind: RunKindCheck, StartedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("insert new: %v", err)
	}
	if err := store.FinishRun("r-new", now.Add(-time.Hour).Add(time.Minute), 0, 3, ""); err != nil {
		t.Fatalf("finish new: %v", err)
	}

	// A second updater on the same system contributes to the sum.
	if err := store.InsertRun(Run{
		ID: "r-pip", SystemID: "sys-1", UpdaterID: "custom.pip",
		Kind: RunKindCheck, StartedAt: now.Add(-30 * time.Minute),
	}); err != nil {
		t.Fatalf("insert pip: %v", err)
	}
	if err := store.FinishRun("r-pip", now.Add(-29*time.Minute), 0, 4, ""); err != nil {
		t.Fatalf("finish pip: %v", err)
	}

	// An apply run on sys-1 must not affect Last Checked.
	if err := store.InsertRun(Run{
		ID: "r-apply", SystemID: "sys-1", UpdaterID: "builtin.dnf",
		Kind: RunKindApply, StartedAt: now,
	}); err != nil {
		t.Fatalf("insert apply: %v", err)
	}
	if err := store.FinishRun("r-apply", now.Add(time.Minute), 0, 3, ""); err != nil {
		t.Fatalf("finish apply: %v", err)
	}

	// Another system, never checked — must not show up in the map.
	if err := store.InsertRun(Run{
		ID: "r-inspect", SystemID: "sys-2", UpdaterID: "",
		Kind: RunKindInspect, StartedAt: now,
	}); err != nil {
		t.Fatalf("insert inspect: %v", err)
	}
	if err := store.FinishRun("r-inspect", now.Add(time.Minute), 0, 0, ""); err != nil {
		t.Fatalf("finish inspect: %v", err)
	}

	stats, err := store.SystemStatsAll()
	if err != nil {
		t.Fatalf("SystemStatsAll: %v", err)
	}
	got, ok := stats["sys-1"]
	if !ok {
		t.Fatalf("sys-1 missing: %+v", stats)
	}
	if got.PendingUpdates != 7 {
		t.Errorf("PendingUpdates = %d, want 7 (3+4 from latest checks)", got.PendingUpdates)
	}
	if got.LastCheckedAt == nil {
		t.Fatalf("LastCheckedAt nil")
	}
	// Last Checked tracks started_at of the newest CHECK run, which
	// is r-pip at now-30m; the apply run is newer but irrelevant.
	wantStart := now.Add(-30 * time.Minute).UTC().Truncate(time.Nanosecond)
	if !got.LastCheckedAt.Equal(wantStart) {
		t.Errorf("LastCheckedAt = %v, want %v", got.LastCheckedAt, wantStart)
	}
	if _, present := stats["sys-2"]; present {
		t.Errorf("sys-2 should be absent (no check runs); got %+v", stats["sys-2"])
	}
}

func TestSystemStatsAllPendingOnlyFinishedRuns(t *testing.T) {
	// A check that started but never finished must not contribute
	// to PendingUpdates (the affected count isn't known yet); it
	// still moves LastCheckedAt forward because the operator asked.
	store := newStore(t)
	now := time.Now().UTC()
	if err := store.InsertRun(Run{
		ID: "r1", SystemID: "sys-1", UpdaterID: "builtin.dnf",
		Kind: RunKindCheck, StartedAt: now,
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// no FinishRun call — still in-flight
	stats, err := store.SystemStatsAll()
	if err != nil {
		t.Fatalf("SystemStatsAll: %v", err)
	}
	got, ok := stats["sys-1"]
	if !ok {
		t.Fatalf("sys-1 missing")
	}
	if got.PendingUpdates != 0 {
		t.Errorf("PendingUpdates = %d, want 0 (in-flight check doesn't count)", got.PendingUpdates)
	}
	if got.LastCheckedAt == nil {
		t.Errorf("LastCheckedAt should track started_at even for in-flight runs")
	}
}

func TestAddAffectedCountColumnIdempotent(t *testing.T) {
	_, _, _, db := newStoreWithSiblings(t)
	if err := addAffectedCountColumn(db); err != nil {
		t.Errorf("second migration: %v", err)
	}
}

// TestAddAffectedCountColumnAddsToLegacyDB exercises the ErrNoRows
// branch of addAffectedCountColumn — the path that runs on a DB
// produced by a System Wrangler release that predates the column.
// We can't get there via NewSQLiteStore (its CREATE TABLE already
// has the column), so the test hand-builds a legacy table shape
// and asserts the migration ALTERs it to spec.
func TestAddAffectedCountColumnAddsToLegacyDB(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/legacy.db"
	db := openLegacyDB(t, dsn)
	t.Cleanup(func() { _ = db.Close() })
	if err := addAffectedCountColumn(db); err != nil {
		t.Fatalf("addAffectedCountColumn: %v", err)
	}
	// Column should now be present.
	var found int
	row := db.QueryRow(`SELECT 1 FROM pragma_table_info('updater_runs') WHERE name = 'affected_count'`)
	if err := row.Scan(&found); err != nil {
		t.Fatalf("post-migration probe: %v", err)
	}
}

func TestSystemStatsAllAffectedCountFromRunner(t *testing.T) {
	// End-to-end sanity for the runner→store→stats path: a Check
	// that returns SW_AFFECTED_COUNT: N must produce stats showing
	// PendingUpdates=N for that system.
	f := newRunnerFixture(t)
	f.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout:   []byte(fmt.Sprintf("\"msg\": \"SW_AFFECTED_COUNT: %d\"\n", 5)),
	}, nil)
	if _, err := f.runner.Check(context.Background(), f.systemID, "builtin.dnf"); err != nil {
		t.Fatalf("Check: %v", err)
	}
	stats, err := f.store.SystemStatsAll()
	if err != nil {
		t.Fatalf("SystemStatsAll: %v", err)
	}
	got := stats[f.systemID]
	if got.PendingUpdates != 5 {
		t.Errorf("PendingUpdates = %d, want 5", got.PendingUpdates)
	}
	if got.LastCheckedAt == nil {
		t.Errorf("LastCheckedAt nil after a check run")
	}
}
