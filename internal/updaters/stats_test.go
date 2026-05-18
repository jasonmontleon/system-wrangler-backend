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

func TestSystemStatsAllAggregatesPendingPackages(t *testing.T) {
	store := newStore(t)
	now := time.Now().UTC()
	// sys-1 has dnf + pip detected and seeded.
	if err := store.UpsertAvailability("sys-1", "builtin.dnf", now); err != nil {
		t.Fatalf("upsert dnf: %v", err)
	}
	if err := store.UpsertAvailability("sys-1", "custom.pip", now); err != nil {
		t.Fatalf("upsert pip: %v", err)
	}
	// "kernel" with identical versions appears on both updaters and
	// must de-dupe; "glibc" and "numpy" are unique.
	dnf := []PendingPackage{
		{Name: "kernel", OldVersion: "6.8.0-31", NewVersion: "6.8.0-45"},
		{Name: "glibc", OldVersion: "2.39-1", NewVersion: "2.39-3"},
	}
	pip := []PendingPackage{
		{Name: "kernel", OldVersion: "6.8.0-31", NewVersion: "6.8.0-45"},
		{Name: "numpy", OldVersion: "1.26.0", NewVersion: "1.26.4"},
	}
	if err := store.SetPendingPackages("sys-1", "builtin.dnf", dnf); err != nil {
		t.Fatalf("set dnf: %v", err)
	}
	if err := store.SetPendingPackages("sys-1", "custom.pip", pip); err != nil {
		t.Fatalf("set pip: %v", err)
	}
	// sys-2: no markers stored.
	if err := store.UpsertAvailability("sys-2", "builtin.dnf", now); err != nil {
		t.Fatalf("upsert sys-2: %v", err)
	}

	stats, err := store.SystemStatsAll()
	if err != nil {
		t.Fatalf("SystemStatsAll: %v", err)
	}
	got := stats["sys-1"].PendingPackages
	want := []PendingPackage{
		{Name: "glibc", OldVersion: "2.39-1", NewVersion: "2.39-3"},
		{Name: "kernel", OldVersion: "6.8.0-31", NewVersion: "6.8.0-45"},
		{Name: "numpy", OldVersion: "1.26.0", NewVersion: "1.26.4"},
	}
	if !equalPendingPackages(got, want) {
		t.Fatalf("PendingPackages = %v, want %v", got, want)
	}
	if pkgs := stats["sys-2"].PendingPackages; len(pkgs) != 0 {
		t.Errorf("sys-2 PendingPackages = %v, want empty", pkgs)
	}
}

func TestSystemStatsAllReportsLastRunFailure(t *testing.T) {
	store := newStore(t)
	now := time.Now().UTC()
	// Most recent run on sys-1 is a failed apply.
	if err := store.InsertRun(Run{
		ID: "r1", SystemID: "sys-1", UpdaterID: "builtin.dnf",
		Kind: RunKindCheck, StartedAt: now.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("insert check: %v", err)
	}
	if err := store.FinishRun("r1", now.Add(-2*time.Hour).Add(time.Minute), 0, 3, ""); err != nil {
		t.Fatalf("finish check: %v", err)
	}
	if err := store.InsertRun(Run{
		ID: "r2", SystemID: "sys-1", UpdaterID: "builtin.dnf",
		Kind: RunKindApply, StartedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("insert apply: %v", err)
	}
	if err := store.FinishRun("r2", now.Add(-time.Hour).Add(time.Minute), 2, 0, "task failed"); err != nil {
		t.Fatalf("finish apply: %v", err)
	}
	// sys-2: most recent run succeeded.
	if err := store.InsertRun(Run{
		ID: "r3", SystemID: "sys-2", UpdaterID: "builtin.dnf",
		Kind: RunKindCheck, StartedAt: now,
	}); err != nil {
		t.Fatalf("insert sys-2: %v", err)
	}
	if err := store.FinishRun("r3", now.Add(time.Minute), 0, 0, ""); err != nil {
		t.Fatalf("finish sys-2: %v", err)
	}
	stats, err := store.SystemStatsAll()
	if err != nil {
		t.Fatalf("SystemStatsAll: %v", err)
	}
	got1 := stats["sys-1"]
	if !got1.LastRunFailed {
		t.Errorf("sys-1 LastRunFailed = false, want true")
	}
	if got1.LastRunReason != "apply exit 2" {
		t.Errorf("sys-1 LastRunReason = %q, want %q", got1.LastRunReason, "apply exit 2")
	}
	got2 := stats["sys-2"]
	if got2.LastRunFailed {
		t.Errorf("sys-2 LastRunFailed = true, want false (most recent run succeeded)")
	}
	if got2.LastRunReason != "" {
		t.Errorf("sys-2 LastRunReason = %q, want empty", got2.LastRunReason)
	}
}

func TestSystemStatsAllIgnoresInFlightForFailure(t *testing.T) {
	// An in-flight run shouldn't be considered the "most recent
	// terminated run" — the previous failure should keep showing.
	store := newStore(t)
	now := time.Now().UTC()
	if err := store.InsertRun(Run{
		ID: "fail", SystemID: "sys-1", UpdaterID: "builtin.dnf",
		Kind: RunKindApply, StartedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("insert fail: %v", err)
	}
	if err := store.FinishRun("fail", now.Add(-time.Hour).Add(time.Minute), 7, 0, ""); err != nil {
		t.Fatalf("finish fail: %v", err)
	}
	// Newer run, still in-flight (no FinishRun call).
	if err := store.InsertRun(Run{
		ID: "inflight", SystemID: "sys-1", UpdaterID: "builtin.dnf",
		Kind: RunKindCheck, StartedAt: now,
	}); err != nil {
		t.Fatalf("insert inflight: %v", err)
	}
	stats, _ := store.SystemStatsAll()
	got := stats["sys-1"]
	if !got.LastRunFailed {
		t.Errorf("LastRunFailed = false, want true (in-flight should be ignored)")
	}
	if got.LastRunReason != "apply exit 7" {
		t.Errorf("LastRunReason = %q", got.LastRunReason)
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
