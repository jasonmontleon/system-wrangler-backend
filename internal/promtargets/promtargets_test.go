// SPDX-License-Identifier: Apache-2.0

package promtargets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/exporters"
	"system-wrangler-backend/internal/systems"
)

func newWriter(t *testing.T) (*Writer, *systems.SQLiteStore, *exporters.SQLiteStore, string) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "promtargets.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	expStore, err := exporters.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("exporters.NewSQLiteStore: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.json")
	w := &Writer{
		Path:          path,
		BackendTarget: "system-wrangler:8080",
		Systems:       sysStore,
		Exporters:     expStore,
	}
	return w, sysStore, expStore, path
}

func TestDefaultBackendTargetIsLoopback(t *testing.T) {
	if DefaultBackendTarget != "127.0.0.1:8080" {
		t.Errorf("DefaultBackendTarget = %q, want 127.0.0.1:8080", DefaultBackendTarget)
	}
}

func TestRegenerateReturnsErrWhenNotConfigured(t *testing.T) {
	w := &Writer{}
	if err := w.Regenerate(context.Background()); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want ErrNotConfigured", err)
	}
}

func TestRegenerateWritesEmptyArrayWithNoInstalls(t *testing.T) {
	w, _, _, path := newWriter(t)
	if err := w.Regenerate(context.Background()); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	body, err := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.TrimSpace(string(body)) != "[]" {
		t.Errorf("body = %q, want []", string(body))
	}
}

func TestRegenerateIncludesInstalledRows(t *testing.T) {
	w, sysStore, expStore, path := newWriter(t)
	sys, err := sysStore.Create(systems.SystemInput{Name: "alpha", Hostname: "alpha.example"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	at := time.Now().UTC()
	if err := expStore.UpsertSystemExporter(exporters.SystemExporter{
		SystemID:     sys.ID,
		ExporterID:   "builtin.dnf.exporter",
		State:        exporters.StateRunning,
		Port:         9100,
		ServiceName:  "node_exporter.service",
		LastStatusAt: &at,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := w.Regenerate(context.Background()); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	body, err := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var entries []Entry
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if len(e.Targets) != 1 || e.Targets[0] != "system-wrangler:8080" {
		t.Errorf("targets = %v", e.Targets)
	}
	if got := e.Labels["__metrics_path__"]; got != "/internal/scrape/"+sys.ID+"/builtin.dnf.exporter" {
		t.Errorf("__metrics_path__ = %q", got)
	}
	if e.Labels["hostname"] != "alpha.example" {
		t.Errorf("hostname = %q", e.Labels["hostname"])
	}
	if e.Labels["exporter_id"] != "builtin.dnf.exporter" {
		t.Errorf("exporter_id = %q", e.Labels["exporter_id"])
	}
}

func TestRegenerateExcludesPausedScrape(t *testing.T) {
	w, sysStore, expStore, path := newWriter(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "p", Hostname: "p.example"})
	at := time.Now().UTC()
	if err := expStore.UpsertSystemExporter(exporters.SystemExporter{
		SystemID:     sys.ID,
		ExporterID:   "builtin.dnf.exporter",
		State:        exporters.StateRunning,
		Port:         9100,
		LastStatusAt: &at,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := expStore.SetScrapeEnabled(sys.ID, "builtin.dnf.exporter", false); err != nil {
		t.Fatalf("set scrape disabled: %v", err)
	}
	if err := w.Regenerate(context.Background()); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	body, _ := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	if strings.TrimSpace(string(body)) != "[]" {
		t.Errorf("body = %q, want [] (paused rows must be excluded)", string(body))
	}
	// Re-enable → row reappears.
	if _, err := expStore.SetScrapeEnabled(sys.ID, "builtin.dnf.exporter", true); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if err := w.Regenerate(context.Background()); err != nil {
		t.Fatalf("re-regen: %v", err)
	}
	body, _ = os.ReadFile(path) //nolint:gosec // t.TempDir() path
	var entries []Entry
	_ = json.Unmarshal(body, &entries)
	if len(entries) != 1 {
		t.Errorf("after re-enable entries = %d, want 1", len(entries))
	}
}

func TestRegenerateExcludesRemoved(t *testing.T) {
	w, sysStore, expStore, path := newWriter(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "rm", Hostname: "rm.example"})
	at := time.Now().UTC()
	_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
		SystemID:     sys.ID,
		ExporterID:   "builtin.dnf.exporter",
		State:        exporters.StateRemoved,
		LastStatusAt: &at,
	})
	if err := w.Regenerate(context.Background()); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	body, _ := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	if strings.TrimSpace(string(body)) != "[]" {
		t.Errorf("body = %q, want [] (removed rows must be excluded)", string(body))
	}
}

func TestRegenerateDeterministicOrder(t *testing.T) {
	w, sysStore, expStore, path := newWriter(t)
	sysA, _ := sysStore.Create(systems.SystemInput{Name: "a", Hostname: "a.example"})
	sysB, _ := sysStore.Create(systems.SystemInput{Name: "b", Hostname: "b.example"})
	at := time.Now().UTC()
	for _, id := range []string{sysB.ID, sysA.ID} {
		_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
			SystemID: id, ExporterID: "builtin.dnf.exporter",
			State: exporters.StateRunning, Port: 9100, LastStatusAt: &at,
		})
	}
	if err := w.Regenerate(context.Background()); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	body, _ := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	var entries []Entry
	_ = json.Unmarshal(body, &entries)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	// Sort by system_id ascending.
	if entries[0].Labels["system_id"] >= entries[1].Labels["system_id"] {
		t.Errorf("not sorted: %v vs %v", entries[0].Labels["system_id"], entries[1].Labels["system_id"])
	}
}

func TestRegenerateIncludesGroupLabel(t *testing.T) {
	w, sysStore, expStore, path := newWriter(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "g", Hostname: "g.example"})
	gid := "group-1"
	if err := sysStore.SetGroup(sys.ID, &gid); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}
	at := time.Now().UTC()
	_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: exporters.StateRunning, Port: 9100, LastStatusAt: &at,
	})
	if err := w.Regenerate(context.Background()); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	body, _ := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	var entries []Entry
	_ = json.Unmarshal(body, &entries)
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Labels["group_id"] != gid {
		t.Errorf("group_id = %q, want %q", entries[0].Labels["group_id"], gid)
	}
}

func TestRegenerateSortsByExporterIDWithinSameSystem(t *testing.T) {
	w, sysStore, expStore, path := newWriter(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "s", Hostname: "s.example"})
	at := time.Now().UTC()
	for _, eid := range []string{"zzz.exporter", "aaa.exporter"} {
		_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
			SystemID: sys.ID, ExporterID: eid,
			State: exporters.StateRunning, Port: 9100, LastStatusAt: &at,
		})
	}
	if err := w.Regenerate(context.Background()); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	body, _ := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	var entries []Entry
	_ = json.Unmarshal(body, &entries)
	if len(entries) != 2 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Labels["exporter_id"] != "aaa.exporter" {
		t.Errorf("first = %q, want aaa.exporter", entries[0].Labels["exporter_id"])
	}
}

func TestRegenerateFailsWhenDirMissing(t *testing.T) {
	w, _, _, _ := newWriter(t)
	w.Path = "/nonexistent-dir-promtargets-test/targets.json"
	if err := w.Regenerate(context.Background()); err == nil {
		t.Error("Regenerate to missing dir = nil, want error")
	}
}

func TestRegenerateSystemsListError(t *testing.T) {
	_, sysStore, expStore, path := newWriter(t)
	w := &Writer{
		Path:          path,
		BackendTarget: "t",
		Systems:       &errListSystems{sysStore},
		Exporters:     expStore,
	}
	err := w.Regenerate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "list systems") {
		t.Errorf("err = %v, want list systems wrap", err)
	}
}

func TestRegenerateExporterListErrorIsSkippedNotFatal(t *testing.T) {
	w, sysStore, _, path := newWriter(t)
	_, _ = sysStore.Create(systems.SystemInput{Name: "ok", Hostname: "ok.example"})
	w.Exporters = &errListExporters{w.Exporters}
	if err := w.Regenerate(context.Background()); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	body, _ := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	if strings.TrimSpace(string(body)) != "[]" {
		t.Errorf("body = %q, want [] (per-system list err must skip)", string(body))
	}
}

type errListSystems struct {
	systems.Store
}

func (e *errListSystems) List() ([]systems.System, error) {
	return nil, errors.New("db down")
}

type errListExporters struct {
	exporters.Store
}

func (e *errListExporters) ListSystemExporters(string) ([]exporters.SystemExporter, error) {
	return nil, errors.New("rows boom")
}

func TestRunInitialRegenerateLogsButContinues(_ *testing.T) {
	w := &Writer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	subscribe := func(func(string)) func() { return func() {} }
	stop := w.Run(ctx, subscribe)
	cancel()
	stop()
}

func TestRunCancelDuringDebounceWindow(t *testing.T) {
	w, sysStore, expStore, _ := newWriter(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "x", Hostname: "x.example"})
	at := time.Now().UTC()
	_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: exporters.StateRunning, Port: 9100, LastStatusAt: &at,
	})
	ctx, cancel := context.WithCancel(context.Background())
	emit := make(chan string, 4)
	subscribe := func(handler func(string)) func() {
		stopCh := make(chan struct{})
		go func() {
			for {
				select {
				case ev := <-emit:
					handler(ev)
				case <-stopCh:
					return
				}
			}
		}()
		return func() { close(stopCh) }
	}
	stop := w.Run(ctx, subscribe)
	emit <- "systems.changed"
	time.Sleep(50 * time.Millisecond) // mid debounce
	cancel()
	stop()
}

func TestRunDebouncesBursts(t *testing.T) {
	w, sysStore, expStore, path := newWriter(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "deb", Hostname: "deb.example"})
	at := time.Now().UTC()
	_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: exporters.StateRunning, Port: 9100, LastStatusAt: &at,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	emitChan := make(chan string, 16)
	subscribe := func(handler func(eventType string)) func() {
		stop := make(chan struct{})
		go func() {
			for {
				select {
				case ev := <-emitChan:
					handler(ev)
				case <-stop:
					return
				}
			}
		}()
		return func() { close(stop) }
	}
	stop := w.Run(ctx, subscribe)
	// Initial regenerate happens — wait for the file.
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		emitChan <- "exporter.run.completed"
	}
	time.Sleep(400 * time.Millisecond)
	cancel()
	stop()
	body, _ := os.ReadFile(path) //nolint:gosec // t.TempDir() path
	var entries []Entry
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("entries = %d, want 1", len(entries))
	}
}
