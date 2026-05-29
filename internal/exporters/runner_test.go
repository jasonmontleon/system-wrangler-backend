// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/systems"
)

// fakeAnsible records calls and returns canned responses queued in
// order. Reuses the updaters test pattern.
type fakeAnsible struct {
	calls     []ansible.Request
	responses []fakeAnsibleResp
}

type fakeAnsibleResp struct {
	run ansible.Run
	err error
}

func (f *fakeAnsible) Run(_ context.Context, req ansible.Request) (ansible.Run, error) {
	f.calls = append(f.calls, req)
	if len(f.responses) == 0 {
		return ansible.Run{Status: ansible.RunSuccess, ExitCode: 0}, nil
	}
	r := f.responses[0]
	f.responses = f.responses[1:]
	return r.run, r.err
}

// memLocker is an in-memory Locker for runner tests. Models the
// minimal contract: one holder per system, idempotent release,
// ConflictingRun returns the current holder or "".
type memLocker struct {
	mu     sync.Mutex
	holder map[string]string
}

func newMemLocker() *memLocker { return &memLocker{holder: map[string]string{}} }

func (m *memLocker) AcquireLock(systemID, runID string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.holder[systemID]; taken {
		return errors.New("another run is in progress")
	}
	m.holder[systemID] = runID
	return nil
}

func (m *memLocker) ReleaseLock(systemID, runID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.holder[systemID] == runID {
		delete(m.holder, systemID)
	}
	return nil
}

func (m *memLocker) ConflictingRun(systemID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.holder[systemID], nil
}

type runnerFixture struct {
	t          *testing.T
	runner     *Runner
	store      *SQLiteStore
	registry   *Registry
	ansible    *fakeAnsible
	locker     *memLocker
	auditStore *audit.Store
	systemID   string
}

func newRunnerFixture(t *testing.T) *runnerFixture {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "runner.db")
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
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	sys, err := sysStore.Create(systems.SystemInput{Name: "host", Hostname: "host.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	reg := NewRegistry(store)
	fa := &fakeAnsible{}
	locker := newMemLocker()
	runner := &Runner{
		Registry: reg,
		Store:    store,
		Locker:   locker,
		Ansible:  fa,
		Audit:    auditStore,
	}
	return &runnerFixture{
		t:          t,
		runner:     runner,
		store:      store,
		registry:   reg,
		ansible:    fa,
		locker:     locker,
		auditStore: auditStore,
		systemID:   sys.ID,
	}
}

func (f *runnerFixture) queue(resp ansible.Run, err error) {
	f.ansible.responses = append(f.ansible.responses, fakeAnsibleResp{run: resp, err: err})
}

func TestInstallSucceedsAndPersistsState(t *testing.T) {
	f := newRunnerFixture(t)
	f.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout: []byte(
			"\"msg\": \"SW_EXPORTER_PORT: 9100\"\n" +
				"\"msg\": \"SW_EXPORTER_SERVICE: node_exporter.service\"\n" +
				"\"msg\": \"SW_EXPORTER_STATE: running\"\n",
		),
	}, nil)
	got := captureNotify(f.runner)
	res, err := f.runner.Install(context.Background(), f.systemID, "builtin.dnf.exporter")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.State != StateRunning {
		t.Errorf("state = %q, want running", res.State)
	}
	if res.Port != 9100 || res.Service != "node_exporter.service" {
		t.Errorf("port/service = %d/%q", res.Port, res.Service)
	}
	row, err := f.store.GetSystemExporter(f.systemID, "builtin.dnf.exporter")
	if err != nil {
		t.Fatalf("GetSystemExporter: %v", err)
	}
	if row.State != StateRunning || row.LastInstallAt == nil {
		t.Errorf("row = %+v", row)
	}
	if len(*got) != 4 {
		t.Errorf("notify events = %d, want 4 (start+changed, complete+changed)", len(*got))
	}
}

func TestInstallAnsibleErrorMarksFailed(t *testing.T) {
	f := newRunnerFixture(t)
	f.queue(ansible.Run{Status: ansible.RunFailure, ExitCode: 2}, errors.New("boom"))
	res, err := f.runner.Install(context.Background(), f.systemID, "builtin.dnf.exporter")
	if err == nil {
		t.Fatal("expected error")
	}
	if res.State != StateFailed {
		t.Errorf("state = %q, want failed", res.State)
	}
	row, err := f.store.GetSystemExporter(f.systemID, "builtin.dnf.exporter")
	if err != nil {
		t.Fatalf("GetSystemExporter: %v", err)
	}
	if row.State != StateFailed {
		t.Errorf("persisted state = %q", row.State)
	}
}

func TestStatusReusesPort(t *testing.T) {
	f := newRunnerFixture(t)
	f.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout: []byte(
			"\"msg\": \"SW_EXPORTER_PORT: 9100\"\n" +
				"\"msg\": \"SW_EXPORTER_SERVICE: node_exporter.service\"\n" +
				"\"msg\": \"SW_EXPORTER_STATE: running\"\n",
		),
	}, nil)
	res, err := f.runner.Status(context.Background(), f.systemID, "builtin.dnf.exporter")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if res.Kind != RunKindStatus {
		t.Errorf("kind = %q", res.Kind)
	}
	if res.Port != 9100 {
		t.Errorf("port = %d", res.Port)
	}
	row, _ := f.store.GetSystemExporter(f.systemID, "builtin.dnf.exporter")
	if row.LastInstallAt != nil {
		t.Errorf("status run should not stamp last_install_at")
	}
	if row.State != StateRunning {
		t.Errorf("state = %q", row.State)
	}
}

func TestRemoveRequiresRemovePlaybook(t *testing.T) {
	f := newRunnerFixture(t)
	// All builtins ship a remove.yml; seed a custom installer without
	// one so we can exercise the ErrNoRemove path.
	d := validDef()
	d.ID = "custom.no-remove"
	if _, err := f.store.CreateCustom(d); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	_, err := f.runner.Remove(context.Background(), f.systemID, "custom.no-remove")
	if !errors.Is(err, ErrNoRemove) {
		t.Errorf("err = %v, want ErrNoRemove", err)
	}
}

func TestRemoveSucceedsAndMarksRow(t *testing.T) {
	f := newRunnerFixture(t)
	// Seed a custom installer with remove.yml + an installed row.
	d := validDef()
	d.ID = "custom.test"
	d.RemovePlaybook = []byte("- hosts: all\n  tasks: []\n")
	if _, err := f.store.CreateCustom(d); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	at := time.Now().UTC()
	_ = f.store.UpsertSystemExporter(SystemExporter{
		SystemID: f.systemID, ExporterID: "custom.test",
		State: StateRunning, LastStatusAt: &at, LastInstallAt: &at,
	})
	f.queue(ansible.Run{Status: ansible.RunSuccess, ExitCode: 0}, nil)
	res, err := f.runner.Remove(context.Background(), f.systemID, "custom.test")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if res.State != StateRemoved {
		t.Errorf("state = %q, want removed", res.State)
	}
	row, _ := f.store.GetSystemExporter(f.systemID, "custom.test")
	if row.State != StateRemoved {
		t.Errorf("persisted state = %q", row.State)
	}
}

func TestConflictWhenLockHeld(t *testing.T) {
	f := newRunnerFixture(t)
	// Hold the lock from another caller.
	if err := f.locker.AcquireLock(f.systemID, "other-run", time.Now()); err != nil {
		t.Fatalf("seed lock: %v", err)
	}
	_, err := f.runner.Install(context.Background(), f.systemID, "builtin.dnf.exporter")
	if !errors.Is(err, ErrConflict) {
		t.Errorf("err = %v, want ErrConflict", err)
	}
}

// errLocker fails AcquireLock with a non-conflict error so the runner
// takes the "lock acquisition failed" branch.
type errLocker struct {
	*memLocker
	acquireErr error
}

func (e *errLocker) AcquireLock(systemID, runID string, at time.Time) error {
	if e.acquireErr != nil {
		return e.acquireErr
	}
	return e.memLocker.AcquireLock(systemID, runID, at)
}

func TestInstallAcquireLockNonConflictError(t *testing.T) {
	f := newRunnerFixture(t)
	f.runner.Locker = &errLocker{memLocker: f.locker, acquireErr: errors.New("locker io")}
	_, err := f.runner.Install(context.Background(), f.systemID, "builtin.dnf.exporter")
	if err == nil || errors.Is(err, ErrConflict) {
		t.Errorf("err = %v, want non-conflict error", err)
	}
}

func TestRunnerNowDefaultsToTimeNow(t *testing.T) {
	r := &Runner{}
	got := r.now()
	if got.IsZero() {
		t.Error("now() = zero time, want time.Now()")
	}
}

func TestRunnerNewIDDefaultsToUUID(t *testing.T) {
	r := &Runner{}
	got := r.newID()
	if got == "" {
		t.Error("newID() = empty, want a generated UUID")
	}
}

func TestRunnerLogStartWithoutAuditIsNoop(_ *testing.T) {
	r := &Runner{} // nil Audit
	// Should not panic.
	r.logStart(context.Background(), audit.Event{Action: "test"})
}

func TestRunnerLogCompleteWithoutAuditIsNoop(_ *testing.T) {
	r := &Runner{} // nil Audit
	// Should not panic.
	r.logComplete(context.Background(), "test", audit.Success, "sys", "parent", time.Now(), audit.Detail{})
}

func TestRunOneRejectsDeletedExporter(t *testing.T) {
	f := newRunnerFixture(t)
	d := Definition{
		ID:                  "custom.delme",
		Source:              SourceCustom,
		DisplayName:         "delme",
		AppliesToPkgManager: "builtin.apt",
		ExporterKind:        KindNodeExporter,
		BindPort:            9100,
		InstallPlaybook:     []byte("- hosts: all\n  tasks: []\n"),
		StatusPlaybook:      []byte("- hosts: all\n  tasks: []\n"),
	}
	if _, err := f.store.CreateCustom(d); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	if err := f.store.DeleteCustom("custom.delme", time.Now().UTC()); err != nil {
		t.Fatalf("DeleteCustom: %v", err)
	}
	_, err := f.runner.Install(context.Background(), f.systemID, "custom.delme")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound (deleted)", err)
	}
}

func TestRunnerRejectsMissingID(t *testing.T) {
	f := newRunnerFixture(t)
	if _, err := f.runner.Install(context.Background(), "", "builtin.dnf.exporter"); !errors.Is(err, ErrInvalid) {
		t.Errorf("missing system_id err = %v", err)
	}
	if _, err := f.runner.Install(context.Background(), f.systemID, ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("missing exporter_id err = %v", err)
	}
	if _, err := f.runner.Install(context.Background(), f.systemID, "builtin.unknown.exporter"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id err = %v", err)
	}
}

func TestRunnerValidateRejectsHalfWired(t *testing.T) {
	r := &Runner{}
	if _, err := r.Install(context.Background(), "s", "x"); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestInstallTrimsHistory(t *testing.T) {
	f := newRunnerFixture(t)
	f.runner.RunHistoryLimit = func() int { return 1 }
	// Seed two stale rows.
	now := time.Now().UTC()
	for i, id := range []string{"r1", "r2"} {
		_ = f.store.InsertRun(Run{
			ID: id, SystemID: f.systemID, ExporterID: "builtin.dnf.exporter",
			Kind: RunKindStatus, StartedAt: now.Add(-time.Duration(10+i) * time.Minute),
		})
	}
	f.queue(ansible.Run{Status: ansible.RunSuccess, ExitCode: 0}, nil)
	if _, err := f.runner.Install(context.Background(), f.systemID, "builtin.dnf.exporter"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rows, _ := f.store.ListRuns(f.systemID, 100)
	if len(rows) > 1 {
		t.Errorf("rows = %d, want at most 1 after trim", len(rows))
	}
}

// captureNotify swaps in a recording Notify and returns the slice
// pointer so tests can inspect the emitted events.
func captureNotify(r *Runner) *[]string {
	var got []string
	r.Notify = func(t string) { got = append(got, t) }
	return &got
}
