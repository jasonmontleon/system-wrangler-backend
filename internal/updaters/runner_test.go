// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/systems"
)

// fakeAnsible records calls and returns canned responses keyed by
// order. Tests rebuild it per case so the response queue stays
// explicit.
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

type runnerFixture struct {
	t          *testing.T
	runner     *Runner
	store      *SQLiteStore
	registry   *Registry
	ansible    *fakeAnsible
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
	if _, err := groups.NewSQLiteStore(db); err != nil {
		t.Fatalf("groups.NewSQLiteStore: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	sys, err := sysStore.Create(systems.SystemInput{Name: "host-x", Hostname: "x.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	reg := NewRegistry(store)
	fa := &fakeAnsible{}
	runner := &Runner{
		Registry: reg,
		Store:    store,
		Ansible:  fa,
		Audit:    auditStore,
	}
	return &runnerFixture{
		t:          t,
		runner:     runner,
		store:      store,
		registry:   reg,
		ansible:    fa,
		auditStore: auditStore,
		systemID:   sys.ID,
	}
}

func (f *runnerFixture) queue(resp ansible.Run, err error) {
	f.ansible.responses = append(f.ansible.responses, fakeAnsibleResp{run: resp, err: err})
}

func TestInspectRecordsDetectedAndEmitsAudit(t *testing.T) {
	f := newRunnerFixture(t)
	f.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout: []byte(
			"TASK [detect builtin.dnf] ********\n" +
				"ok: [x.example] => { \"msg\": \"SW_DETECTED: builtin.dnf\" }\n",
		),
	}, nil)

	res, err := f.runner.Inspect(context.Background(), f.systemID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if res.Status != ansible.RunSuccess {
		t.Errorf("status = %q, want success", res.Status)
	}
	if len(res.Detected) != 1 || res.Detected[0] != "builtin.dnf" {
		t.Errorf("detected = %v, want [builtin.dnf]", res.Detected)
	}
	if len(f.ansible.calls) != 1 || !f.ansible.calls[0].OmitAudit {
		t.Errorf("OmitAudit must be set on the wrapped request: %+v", f.ansible.calls)
	}

	avail, _ := f.store.AvailabilityFor(f.systemID)
	if len(avail) != 1 || avail[0].UpdaterID != "builtin.dnf" {
		t.Errorf("availability = %v", avail)
	}

	// Audit pair: start + complete.
	verifyAuditPair(t, f.auditStore, "system.inspect.start", "system.inspect.complete", res.Run.ID)
}

func TestInspectRemovesDisappearedUpdaters(t *testing.T) {
	f := newRunnerFixture(t)
	// Seed a stale availability row that the next inspection won't
	// confirm.
	if err := f.store.UpsertAvailability(f.systemID, "builtin.dnf", time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	f.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout:   []byte("nothing detected\n"),
	}, nil)

	res, err := f.runner.Inspect(context.Background(), f.systemID)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "builtin.dnf" {
		t.Errorf("removed = %v, want [builtin.dnf]", res.Removed)
	}
	avail, _ := f.store.AvailabilityFor(f.systemID)
	if len(avail) != 0 {
		t.Errorf("availability survived removal: %v", avail)
	}
}

func TestCheckEmitsPairAndStoresRun(t *testing.T) {
	f := newRunnerFixture(t)
	f.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout:   []byte("\"msg\": \"SW_AFFECTED_COUNT: 7\"\n"),
	}, nil)
	res, err := f.runner.Check(context.Background(), f.systemID, "builtin.dnf")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.AffectedCount != 7 {
		t.Errorf("AffectedCount = %d, want 7", res.AffectedCount)
	}
	runs, _ := f.store.ListRuns(f.systemID, 10)
	if len(runs) != 1 || runs[0].Kind != RunKindCheck {
		t.Fatalf("runs = %+v", runs)
	}
	if runs[0].ExitCode == nil || *runs[0].ExitCode != 0 {
		t.Errorf("exit_code = %v, want 0", runs[0].ExitCode)
	}
	verifyAuditPair(t, f.auditStore, "system.update.check.start", "system.update.check.complete", res.Run.ID)
}

func TestApplyEmitsAffectedAndLogSha(t *testing.T) {
	f := newRunnerFixture(t)
	f.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout:   []byte("output...\n\"msg\": \"SW_AFFECTED_COUNT: 3\"\n"),
	}, nil)
	res, err := f.runner.Apply(context.Background(), f.systemID, "builtin.dnf")
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.AffectedCount != 3 {
		t.Errorf("AffectedCount = %d, want 3", res.AffectedCount)
	}
	// Verify the complete row carries affected_packages and log_sha.
	rows := auditRowsWithAction(t, f.auditStore, "system.update.apply.complete")
	if len(rows) != 1 {
		t.Fatalf("complete rows = %d, want 1", len(rows))
	}
	d := rows[0].Detail
	if got, _ := d["affected_packages"].(float64); int(got) != 3 {
		// audit JSON round-trip can return numbers as float64 or int
		// depending on the driver; accept either.
		if iGot, _ := d["affected_packages"].(int); iGot != 3 {
			t.Errorf("affected_packages = %v, want 3", d["affected_packages"])
		}
	}
	if _, ok := d["log_sha"].(string); !ok {
		t.Errorf("log_sha missing or not string: %v", d["log_sha"])
	}
	if _, ok := d["parent_id"].(string); !ok {
		t.Errorf("parent_id missing: %v", d)
	}
}

func TestCheckRejectsUnknownUpdater(t *testing.T) {
	f := newRunnerFixture(t)
	if _, err := f.runner.Check(context.Background(), f.systemID, "builtin.nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCheckRejectsDeletedCustom(t *testing.T) {
	f := newRunnerFixture(t)
	if _, err := f.registry.CreateCustom(sampleDef("custom.scratch")); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	if err := f.registry.DeleteCustom("custom.scratch", time.Now()); err != nil {
		t.Fatalf("DeleteCustom: %v", err)
	}
	if _, err := f.runner.Check(context.Background(), f.systemID, "custom.scratch"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestApplyConflictWhenLockHeld(t *testing.T) {
	f := newRunnerFixture(t)
	// Take the lock with a foreign run id; the runner's apply must
	// fail with ErrConflict.
	if err := f.store.AcquireLock(f.systemID, "outside-run", time.Now()); err != nil {
		t.Fatalf("seed lock: %v", err)
	}
	f.queue(ansible.Run{Status: ansible.RunSuccess}, nil)
	res, err := f.runner.Apply(context.Background(), f.systemID, "builtin.dnf")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	if res.Reason != "conflict" {
		t.Errorf("reason = %q, want conflict", res.Reason)
	}
	// The fake ansible must NOT have been called for the conflicting
	// run.
	if len(f.ansible.calls) != 0 {
		t.Errorf("ansible was invoked despite lock: %+v", f.ansible.calls)
	}
}

func TestRunnerValidateRejectsUnwired(t *testing.T) {
	r := &Runner{}
	if _, err := r.Inspect(context.Background(), "sys"); !errors.Is(err, ErrInvalid) {
		t.Errorf("Inspect: err = %v, want ErrInvalid", err)
	}
	if _, err := r.Check(context.Background(), "sys", "builtin.dnf"); !errors.Is(err, ErrInvalid) {
		t.Errorf("Check: err = %v, want ErrInvalid", err)
	}
}

func TestRunnerCheckEmptyArgs(t *testing.T) {
	f := newRunnerFixture(t)
	if _, err := f.runner.Check(context.Background(), "", "builtin.dnf"); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty system: err = %v, want ErrInvalid", err)
	}
	if _, err := f.runner.Check(context.Background(), "sys", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty updater: err = %v, want ErrInvalid", err)
	}
}

func TestRunnerCheckPropagatesAnsibleError(t *testing.T) {
	f := newRunnerFixture(t)
	f.queue(ansible.Run{Status: ansible.RunFailure, ExitCode: -1}, errors.New("exec died"))
	res, err := f.runner.Check(context.Background(), f.systemID, "builtin.dnf")
	if err == nil {
		t.Fatalf("err = nil, want propagated")
	}
	if res.Status != ansible.RunFailure {
		t.Errorf("status = %q, want failure", res.Status)
	}
	rows := auditRowsWithAction(t, f.auditStore, "system.update.check.complete")
	if len(rows) != 1 || rows[0].Outcome != audit.Failure {
		t.Errorf("audit complete outcome = %+v", rows)
	}
}

func TestPlaybookComposerWalksRegistry(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)
	defs, _ := reg.All()
	body := inspectionPlaybook(defs)
	for _, d := range defs {
		if !strings.Contains(string(body), "detect "+d.ID) {
			t.Errorf("inspection playbook missing detect task for %q:\n%s", d.ID, body)
		}
		if !strings.Contains(string(body), "command -v "+d.DetectBinary) {
			t.Errorf("inspection playbook missing command -v for %q", d.DetectBinary)
		}
	}
}

func TestParseDetected(t *testing.T) {
	out := []byte(
		`TASK [emit builtin.dnf] *****` + "\n" +
			`ok: [host] => { "msg": "SW_DETECTED: builtin.dnf" }` + "\n" +
			`TASK [emit custom.foo] ******` + "\n" +
			`ok: [host] => { "msg": "SW_DETECTED: custom.foo" }` + "\n" +
			`unrelated noise` + "\n",
	)
	got := parseDetected(out)
	if !got["builtin.dnf"] || !got["custom.foo"] {
		t.Errorf("parseDetected = %v", got)
	}
}

func TestParseAffectedCount(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{`ok: [h] => { "msg": "SW_AFFECTED_COUNT: 12" }`, 12},
		{"SW_AFFECTED_COUNT: 0\n", 0},
		{"no marker here\n", 0},
		{"SW_AFFECTED_COUNT: bogus\n", 0},
	}
	for _, tt := range cases {
		if got := parseAffectedCount([]byte(tt.in)); got != tt.want {
			t.Errorf("parseAffectedCount(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

// verifyAuditPair asserts both rows are present and the complete's
// detail.parent_id equals the start's id (== runID).
func verifyAuditPair(t *testing.T, store *audit.Store, startAction, completeAction, runID string) {
	t.Helper()
	starts := auditRowsWithAction(t, store, startAction)
	completes := auditRowsWithAction(t, store, completeAction)
	if len(starts) != 1 {
		t.Errorf("%q row count = %d, want 1", startAction, len(starts))
	}
	if len(completes) != 1 {
		t.Errorf("%q row count = %d, want 1", completeAction, len(completes))
	}
	if len(starts) == 1 && starts[0].ID != runID {
		t.Errorf("start row id = %q, want %q", starts[0].ID, runID)
	}
	if len(completes) == 1 {
		parent, _ := completes[0].Detail["parent_id"].(string)
		if parent != runID {
			t.Errorf("complete parent_id = %q, want %q", parent, runID)
		}
	}
}

func auditRowsWithAction(t *testing.T, store *audit.Store, action string) []audit.Record {
	t.Helper()
	rows, _, err := store.ListQuery(audit.Query{Action: action, Limit: 50})
	if err != nil {
		t.Fatalf("audit ListQuery(%q): %v", action, err)
	}
	return rows
}

// Keep strings import honest for the playbook composer test.
var _ = strings.Contains
