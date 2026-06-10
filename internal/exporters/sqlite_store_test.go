// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/systems"
)

func newStore(t *testing.T) *SQLiteStore {
	t.Helper()
	store, _, _ := newStoreWithSystems(t)
	return store
}

// newStoreWithSystems opens a fresh temp DB plus the systems store
// so the cascade triggers on hosts have a real parent table.
func newStoreWithSystems(t *testing.T) (*SQLiteStore, *systems.SQLiteStore, *sql.DB) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "exporters.db")
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
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return store, sysStore, db
}

func TestNewSQLiteStoreIdempotent(t *testing.T) {
	_, _, db := newStoreWithSystems(t)
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("second NewSQLiteStore: %v", err)
	}
}

func TestCustomCRUDRoundTrip(t *testing.T) {
	store := newStore(t)

	d := validDef()
	d.ID = "custom.alpha"
	created, err := store.CreateCustom(d)
	if err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("timestamps not stamped: %+v", created)
	}
	got, err := store.GetCustom("custom.alpha")
	if err != nil {
		t.Fatalf("GetCustom: %v", err)
	}
	if got.DisplayName != d.DisplayName {
		t.Errorf("display = %q, want %q", got.DisplayName, d.DisplayName)
	}

	// Duplicate id triggers ErrDuplicate.
	if _, err := store.CreateCustom(d); !errors.Is(err, ErrDuplicate) {
		t.Errorf("dup err = %v, want ErrDuplicate", err)
	}

	d.DisplayName = "Updated"
	if _, err := store.UpdateCustom(d); err != nil {
		t.Fatalf("UpdateCustom: %v", err)
	}
	got, err = store.GetCustom("custom.alpha")
	if err != nil {
		t.Fatalf("GetCustom after update: %v", err)
	}
	if got.DisplayName != "Updated" {
		t.Errorf("display after update = %q", got.DisplayName)
	}

	if err := store.DeleteCustom("custom.alpha", time.Now()); err != nil {
		t.Fatalf("DeleteCustom: %v", err)
	}
	if _, err := store.UpdateCustom(d); !errors.Is(err, ErrNotFound) {
		t.Errorf("update after delete err = %v, want ErrNotFound", err)
	}
	got, err = store.GetCustom("custom.alpha")
	if err != nil {
		t.Fatalf("GetCustom soft-deleted: %v", err)
	}
	if !got.IsDeleted() {
		t.Errorf("soft-deleted row should report IsDeleted true")
	}
	// Soft-deleted rows are excluded from ListCustom.
	rows, err := store.ListCustom()
	if err != nil {
		t.Fatalf("ListCustom: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("ListCustom returned %d rows after soft delete", len(rows))
	}
	if err := store.DeleteCustom("custom.alpha", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("re-delete err = %v, want ErrNotFound", err)
	}
}

func TestCreateCustomRejectsBadID(t *testing.T) {
	store := newStore(t)
	d := validDef()
	d.ID = "builtin.bad"
	if _, err := store.CreateCustom(d); !errors.Is(err, ErrReservedID) {
		t.Errorf("err = %v, want ErrReservedID", err)
	}
}

func TestCreateCustomRejectsInvalid(t *testing.T) {
	store := newStore(t)
	d := validDef()
	d.ID = "custom.bad"
	d.AppliesToPkgManager = "" // breaks Validate
	_, err := store.CreateCustom(d)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid wrap", err)
	}
}

func seedSystem(t *testing.T, sysStore *systems.SQLiteStore, name string) systems.System {
	t.Helper()
	sys, err := sysStore.Create(systems.SystemInput{Name: name, Hostname: name + ".example"})
	if err != nil {
		t.Fatalf("seed system: %v", err)
	}
	return sys
}

func TestSystemExporterUpsertAndRemove(t *testing.T) {
	store, sysStore, _ := newStoreWithSystems(t)
	sys := seedSystem(t, sysStore, "host1")

	at := time.Now().UTC().Truncate(time.Second)
	row := SystemExporter{
		SystemID:      sys.ID,
		ExporterID:    "builtin.dnf.exporter",
		State:         StateRunning,
		Port:          9100,
		ServiceName:   "node_exporter.service",
		LastStatusAt:  &at,
		LastInstallAt: &at,
	}
	if err := store.UpsertSystemExporter(row); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := store.GetSystemExporter(sys.ID, "builtin.dnf.exporter")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != StateRunning || got.Port != 9100 || got.ServiceName != "node_exporter.service" {
		t.Errorf("unexpected row: %+v", got)
	}

	// Second upsert without LastInstallAt must preserve the previous one.
	later := at.Add(time.Minute)
	row2 := SystemExporter{
		SystemID:     sys.ID,
		ExporterID:   "builtin.dnf.exporter",
		State:        StateFailed,
		Port:         9100,
		ServiceName:  "node_exporter.service",
		LastStatusAt: &later,
		LastReason:   "unit not active",
	}
	if err := store.UpsertSystemExporter(row2); err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	got, err = store.GetSystemExporter(sys.ID, "builtin.dnf.exporter")
	if err != nil {
		t.Fatalf("get 2: %v", err)
	}
	if got.LastInstallAt == nil || !got.LastInstallAt.Equal(at) {
		t.Errorf("LastInstallAt not preserved: got %v, want %v", got.LastInstallAt, at)
	}
	if got.State != StateFailed {
		t.Errorf("state not updated: %v", got.State)
	}

	// MarkRemoved on a known row.
	if err := store.MarkRemoved(sys.ID, "builtin.dnf.exporter", later, "operator removed"); err != nil {
		t.Fatalf("mark removed: %v", err)
	}
	got, err = store.GetSystemExporter(sys.ID, "builtin.dnf.exporter")
	if err != nil {
		t.Fatalf("get 3: %v", err)
	}
	if got.State != StateRemoved {
		t.Errorf("state after remove = %v, want removed", got.State)
	}
	// MarkRemoved on unknown returns ErrNotFound.
	if err := store.MarkRemoved(sys.ID, "builtin.unknown", later, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("mark removed unknown err = %v", err)
	}
}

func TestSystemExporterRejectsBadInput(t *testing.T) {
	store := newStore(t)
	if err := store.UpsertSystemExporter(SystemExporter{ExporterID: "x", State: StateRunning}); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty system_id err = %v, want ErrInvalid", err)
	}
	if err := store.UpsertSystemExporter(SystemExporter{SystemID: "s", ExporterID: "e", State: "bogus"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("bogus state err = %v, want ErrInvalid", err)
	}
}

func TestListSystemExporters(t *testing.T) {
	store, sysStore, _ := newStoreWithSystems(t)
	sys := seedSystem(t, sysStore, "host2")

	at := time.Now().UTC()
	_ = store.UpsertSystemExporter(SystemExporter{SystemID: sys.ID, ExporterID: "a", State: StateRunning, LastStatusAt: &at})
	_ = store.UpsertSystemExporter(SystemExporter{SystemID: sys.ID, ExporterID: "b", State: StateInstalled, LastStatusAt: &at})

	rows, err := store.ListSystemExporters(sys.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("len = %d, want 2", len(rows))
	}
	if rows[0].ExporterID != "a" || rows[1].ExporterID != "b" {
		t.Errorf("ordering not by exporter_id: %v", rows)
	}
}

func TestGetSettingsDefault(t *testing.T) {
	store := newStore(t)
	got, err := store.GetSettings("missing")
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got.ScrapeMode != ScrapeLocalhost {
		t.Errorf("default mode = %q, want localhost", got.ScrapeMode)
	}
	if got.SystemID != "missing" {
		t.Errorf("system id = %q, want %q", got.SystemID, "missing")
	}
}

func TestSetScrapeModeUpsert(t *testing.T) {
	store := newStore(t)
	if err := store.SetScrapeMode("sys", ScrapeMTLSSelf); err != nil {
		t.Fatalf("SetScrapeMode: %v", err)
	}
	got, err := store.GetSettings("sys")
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if got.ScrapeMode != ScrapeMTLSSelf {
		t.Errorf("mode = %q, want mtls-self", got.ScrapeMode)
	}
	if err := store.SetScrapeMode("sys", ScrapeLocalhost); err != nil {
		t.Fatalf("update SetScrapeMode: %v", err)
	}
	got, _ = store.GetSettings("sys")
	if got.ScrapeMode != ScrapeLocalhost {
		t.Errorf("updated mode = %q", got.ScrapeMode)
	}
	if err := store.SetScrapeMode("", ScrapeLocalhost); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty system_id err = %v, want ErrInvalid", err)
	}
	if err := store.SetScrapeMode("sys", ScrapeMode("bogus")); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid mode err = %v, want ErrInvalid", err)
	}
}

func TestRunCRUD(t *testing.T) {
	store := newStore(t)
	now := time.Now().UTC()
	r := Run{
		ID:        "run-1",
		SystemID:  "sys-1",
		Kind:      RunKindInstall,
		StartedAt: now,
	}
	if err := store.InsertRun(r); err != nil {
		t.Fatalf("InsertRun: %v", err)
	}
	// Bad kind rejected.
	if err := store.InsertRun(Run{ID: "x", SystemID: "s", Kind: "bogus", StartedAt: now}); !errors.Is(err, ErrInvalid) {
		t.Errorf("bogus kind err = %v", err)
	}
	finished := now.Add(time.Second)
	tail := strings.Repeat("x", MaxLogTailBytes*2)
	if err := store.FinishRun("run-1", finished, 0, tail); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}
	rows, err := store.ListRuns("sys-1", 10)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].ExitCode == nil || *rows[0].ExitCode != 0 {
		t.Errorf("exit = %v", rows[0].ExitCode)
	}
	if len(rows[0].LogTail) > MaxLogTailBytes {
		t.Errorf("log tail not truncated: %d", len(rows[0].LogTail))
	}
	if err := store.FinishRun("missing", finished, 0, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("finish missing err = %v", err)
	}
}

func TestReconcileOrphanedRuns(t *testing.T) {
	store := newStore(t)
	now := time.Now().UTC()
	// In-flight install from a dead process.
	if err := store.InsertRun(Run{
		ID: "run-orphan", SystemID: "sys-1", ExporterID: "x",
		Kind: RunKindInstall, StartedAt: now,
	}); err != nil {
		t.Fatalf("InsertRun orphan: %v", err)
	}
	// A finished run that must stay untouched.
	if err := store.InsertRun(Run{
		ID: "run-done", SystemID: "sys-2", ExporterID: "x",
		Kind: RunKindStatus, StartedAt: now,
	}); err != nil {
		t.Fatalf("InsertRun done: %v", err)
	}
	if err := store.FinishRun("run-done", now.Add(time.Second), 0, "ok"); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}

	n, err := store.ReconcileOrphanedRuns(now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ReconcileOrphanedRuns: %v", err)
	}
	if n != 1 {
		t.Fatalf("finalized = %d, want 1", n)
	}

	orphan, err := store.ListRuns("sys-1", 10)
	if err != nil || len(orphan) != 1 {
		t.Fatalf("ListRuns sys-1: %v len=%d", err, len(orphan))
	}
	if orphan[0].FinishedAt == nil {
		t.Error("orphan finished_at still null")
	}
	if orphan[0].ExitCode == nil || *orphan[0].ExitCode != InterruptedExitCode {
		t.Errorf("orphan exit = %v, want %d", orphan[0].ExitCode, InterruptedExitCode)
	}

	done, _ := store.ListRuns("sys-2", 10)
	if done[0].ExitCode == nil || *done[0].ExitCode != 0 {
		t.Errorf("clean run exit = %v, want 0 (untouched)", done[0].ExitCode)
	}

	n2, err := store.ReconcileOrphanedRuns(now.Add(2 * time.Minute))
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if n2 != 0 {
		t.Errorf("second pass finalized = %d, want 0", n2)
	}
}

func TestTrimRunsForSystem(t *testing.T) {
	store := newStore(t)
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		_ = store.InsertRun(Run{ID: idStr(i), SystemID: "sys", Kind: RunKindStatus, StartedAt: now.Add(time.Duration(i) * time.Minute)})
	}
	if err := store.TrimRunsForSystem("sys", 3); err != nil {
		t.Fatalf("Trim: %v", err)
	}
	rows, _ := store.ListRuns("sys", 100)
	if len(rows) != 3 {
		t.Errorf("rows after trim = %d, want 3", len(rows))
	}
	// Non-positive keep is a no-op.
	if err := store.TrimRunsForSystem("sys", 0); err != nil {
		t.Errorf("Trim with 0: %v", err)
	}
	if err := store.TrimRunsForSystem("", 1); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty system_id err = %v", err)
	}
}

func idStr(i int) string {
	// i is loop-bounded to small positive values in tests; the
	// conversion stays within rune range.
	return string(rune('a'+i)) + "-id" //nolint:gosec // bounded test input
}

func TestCascadeOnSystemDelete(t *testing.T) {
	store, sysStore, _ := newStoreWithSystems(t)
	sys := seedSystem(t, sysStore, "doomed")

	at := time.Now().UTC()
	if err := store.UpsertSystemExporter(SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: StateRunning, LastStatusAt: &at,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := store.SetScrapeMode(sys.ID, ScrapeLocalhost); err != nil {
		t.Fatalf("scrape: %v", err)
	}
	if err := store.InsertRun(Run{
		ID: "r1", SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		Kind: RunKindStatus, StartedAt: at,
	}); err != nil {
		t.Fatalf("run: %v", err)
	}

	if err := sysStore.Delete(sys.ID); err != nil {
		t.Fatalf("delete system: %v", err)
	}

	rows, _ := store.ListSystemExporters(sys.ID)
	if len(rows) != 0 {
		t.Errorf("system_exporters not cascaded: %d", len(rows))
	}
	runs, _ := store.ListRuns(sys.ID, 100)
	if len(runs) != 0 {
		t.Errorf("exporter_runs not cascaded: %d", len(runs))
	}
}

func TestNewSystemExporterDefaultsScrapeEnabled(t *testing.T) {
	store, sysStore, _ := newStoreWithSystems(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "a", Hostname: "a.example"})
	now := time.Now().UTC()
	if err := store.UpsertSystemExporter(SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: StateRunning, Port: 9100, LastStatusAt: &now,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := store.GetSystemExporter(sys.ID, "builtin.dnf.exporter")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.ScrapeEnabled {
		t.Errorf("new row ScrapeEnabled = false, want true")
	}
}

func TestSetScrapeEnabledChangedThenIdempotent(t *testing.T) {
	store, sysStore, _ := newStoreWithSystems(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "a", Hostname: "a.example"})
	now := time.Now().UTC()
	_ = store.UpsertSystemExporter(SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: StateRunning, Port: 9100, LastStatusAt: &now,
	})

	changed, err := store.SetScrapeEnabled(sys.ID, "builtin.dnf.exporter", false)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if !changed {
		t.Errorf("first disable: changed = false, want true")
	}
	got, _ := store.GetSystemExporter(sys.ID, "builtin.dnf.exporter")
	if got.ScrapeEnabled {
		t.Errorf("after disable, ScrapeEnabled = true")
	}

	changed, err = store.SetScrapeEnabled(sys.ID, "builtin.dnf.exporter", false)
	if err != nil {
		t.Fatalf("re-disable: %v", err)
	}
	if changed {
		t.Errorf("re-disable: changed = true, want false (idempotent)")
	}

	changed, _ = store.SetScrapeEnabled(sys.ID, "builtin.dnf.exporter", true)
	if !changed {
		t.Errorf("re-enable: changed = false, want true")
	}
}

func TestSetScrapeEnabledMissingRowReturnsNotFound(t *testing.T) {
	store := newStore(t)
	changed, err := store.SetScrapeEnabled("ghost-sys", "builtin.dnf.exporter", false)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if changed {
		t.Errorf("changed = true on missing row")
	}
}

func TestUpsertPreservesScrapeEnabled(t *testing.T) {
	store, sysStore, _ := newStoreWithSystems(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "a", Hostname: "a.example"})
	now := time.Now().UTC()
	_ = store.UpsertSystemExporter(SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: StateRunning, Port: 9100, LastStatusAt: &now,
	})
	if _, err := store.SetScrapeEnabled(sys.ID, "builtin.dnf.exporter", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	// A subsequent status upsert must not flip scrape_enabled back to
	// true — pause is operator state, not observed state.
	later := now.Add(time.Minute)
	_ = store.UpsertSystemExporter(SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: StateRunning, Port: 9100, LastStatusAt: &later,
	})
	got, _ := store.GetSystemExporter(sys.ID, "builtin.dnf.exporter")
	if got.ScrapeEnabled {
		t.Errorf("status upsert reset ScrapeEnabled; want false")
	}
}

// TestScrapeEnabledMigratesLegacyDB exercises the pragma-probe migration
// against a hand-built legacy schema lacking the scrape_enabled column,
// the path that runs on an upgrade from a pre-pause release.
func TestScrapeEnabledMigratesLegacyDB(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/legacy.db"
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE system_exporters (
		system_id        TEXT NOT NULL,
		exporter_id      TEXT NOT NULL,
		state            TEXT NOT NULL,
		port             INTEGER NOT NULL DEFAULT 0,
		service_name     TEXT NOT NULL DEFAULT '',
		last_status_at   INTEGER,
		last_install_at  INTEGER,
		last_reason      TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (system_id, exporter_id)
	) STRICT`); err != nil {
		t.Fatalf("legacy: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO system_exporters (system_id, exporter_id, state) VALUES (?, ?, 'installed')`,
		"sys-1", "builtin.dnf.exporter",
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := addScrapeEnabledColumn(db); err != nil {
		t.Fatalf("migration: %v", err)
	}
	var n int
	if err := db.QueryRow(
		`SELECT scrape_enabled FROM system_exporters WHERE system_id = ?`,
		"sys-1",
	).Scan(&n); err != nil {
		t.Fatalf("post-migration probe: %v", err)
	}
	if n != 1 {
		t.Errorf("legacy row scrape_enabled = %d, want 1 (default for upgrade)", n)
	}
	if err := addScrapeEnabledColumn(db); err != nil {
		t.Errorf("second migration call must be a no-op: %v", err)
	}
}

// TestSQLiteStoreClosedDBSurfacesErrors closes the underlying *sql.DB
// then calls every store method asserting each returns a non-nil
// error. Bulk-covers the "if err := db.{Exec,Query,QueryRow}(...);
// err != nil { return fmt.Errorf(...) }" branch per method without
// duplicating per-method fixtures.
func TestSQLiteStoreClosedDBSurfacesErrors(t *testing.T) {
	store, _, db := newStoreWithSystems(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	type call struct {
		name string
		fn   func() error
	}
	calls := []call{
		{"ListCustom", func() error { _, err := store.ListCustom(); return err }},
		{"GetCustom", func() error { _, err := store.GetCustom("x"); return err }},
		{"CreateCustom", func() error {
			_, err := store.CreateCustom(Definition{
				ID: "custom.x", Source: SourceCustom, DisplayName: "x",
				AppliesToPkgManager: "builtin.apt", ExporterKind: KindNodeExporter,
				BindPort:        9100,
				InstallPlaybook: []byte("- hosts: all\n  tasks: []\n"),
				StatusPlaybook:  []byte("- hosts: all\n  tasks: []\n"),
			})
			return err
		}},
		{"UpdateCustom", func() error {
			_, err := store.UpdateCustom(Definition{
				ID: "custom.x", Source: SourceCustom, DisplayName: "x",
				AppliesToPkgManager: "builtin.apt", ExporterKind: KindNodeExporter,
				BindPort:        9100,
				InstallPlaybook: []byte("- hosts: all\n  tasks: []\n"),
				StatusPlaybook:  []byte("- hosts: all\n  tasks: []\n"),
			})
			return err
		}},
		{"DeleteCustom", func() error { return store.DeleteCustom("custom.x", time.Now()) }},
		{"UpsertSystemExporter", func() error {
			return store.UpsertSystemExporter(SystemExporter{
				SystemID: "s", ExporterID: "x", State: StateRunning, Port: 9100,
			})
		}},
		{"GetSystemExporter", func() error { _, err := store.GetSystemExporter("s", "x"); return err }},
		{"ListSystemExporters", func() error { _, err := store.ListSystemExporters("s"); return err }},
		{"SetScrapeEnabled", func() error { _, err := store.SetScrapeEnabled("s", "x", true); return err }},
		{"MarkRemoved", func() error { return store.MarkRemoved("s", "x", time.Now(), "r") }},
		{"GetSettings", func() error { _, err := store.GetSettings("s"); return err }},
		{"SetScrapeMode", func() error { return store.SetScrapeMode("s", ScrapeLocalhost) }},
		{"InsertRun", func() error {
			return store.InsertRun(Run{ID: "r", SystemID: "s", ExporterID: "x", Kind: RunKindStatus, StartedAt: time.Now()})
		}},
		{"FinishRun", func() error { return store.FinishRun("r", time.Now(), 0, "") }},
		{"ListRuns", func() error { _, err := store.ListRuns("s", 10); return err }},
		{"TrimRunsForSystem", func() error { return store.TrimRunsForSystem("s", 1) }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(); err == nil {
				t.Errorf("%s on closed DB returned nil error, expected failure", c.name)
			}
		})
	}
}
