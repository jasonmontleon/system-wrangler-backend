// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
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

func TestCheckPersistsPendingPackages(t *testing.T) {
	f := newRunnerFixture(t)
	// Seed availability so SetPendingPackages has a row to update.
	if err := f.store.UpsertAvailability(f.systemID, "builtin.dnf", time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	f.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout: []byte(
			"\"msg\": \"SW_AFFECTED_COUNT: 2\"\n" +
				"\"msg\": \"SW_PENDING_PACKAGE: kernel|6.8.0-31|6.8.0-45\"\n" +
				"\"msg\": \"SW_PENDING_PACKAGE: glibc|2.39-1|2.39-3\"\n",
		),
	}, nil)
	if _, err := f.runner.Check(context.Background(), f.systemID, "builtin.dnf"); err != nil {
		t.Fatalf("Check: %v", err)
	}
	avail, _ := f.store.AvailabilityFor(f.systemID)
	if len(avail) != 1 {
		t.Fatalf("avail = %+v", avail)
	}
	got := avail[0].PendingPackages
	want := []PendingPackage{
		{Name: "kernel", OldVersion: "6.8.0-31", NewVersion: "6.8.0-45"},
		{Name: "glibc", OldVersion: "2.39-1", NewVersion: "2.39-3"},
	}
	if !equalPendingPackages(got, want) {
		t.Errorf("PendingPackages = %v, want %v", got, want)
	}
}

func TestApplyDoesNotPersistPendingPackages(t *testing.T) {
	f := newRunnerFixture(t)
	// Seed a populated list so we can verify Apply does not clobber
	// it. The auto-Check-after-Apply lives client-side; the server-
	// side Apply must leave the list alone.
	if err := f.store.UpsertAvailability(f.systemID, "builtin.dnf", time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	seed := []PendingPackage{{Name: "keep-me", OldVersion: "1.0", NewVersion: "2.0"}}
	if err := f.store.SetPendingPackages(f.systemID, "builtin.dnf", seed); err != nil {
		t.Fatalf("seed packages: %v", err)
	}
	f.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout: []byte(
			"\"msg\": \"SW_AFFECTED_COUNT: 1\"\n" +
				"\"msg\": \"SW_PENDING_PACKAGE: ignore-me|9.0|9.1\"\n",
		),
	}, nil)
	if _, err := f.runner.Apply(context.Background(), f.systemID, "builtin.dnf"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	avail, _ := f.store.AvailabilityFor(f.systemID)
	if len(avail) != 1 || !equalPendingPackages(avail[0].PendingPackages, seed) {
		t.Errorf("PendingPackages = %v, want %v (apply must not overwrite)", avail[0].PendingPackages, seed)
	}
}

func equalPendingPackages(a, b []PendingPackage) bool {
	return slices.Equal(a, b)
}

func TestCheckTrimsRunHistoryAfterInsert(t *testing.T) {
	f := newRunnerFixture(t)
	f.runner.RunHistoryLimit = func() int { return 2 }
	// Seed three pre-existing rows, then drive a check; the runner
	// must trim back to 2 (the new run plus the newest survivor).
	base := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := f.store.InsertRun(Run{
			ID: "old-" + strconv.Itoa(i), SystemID: f.systemID,
			UpdaterID: "builtin.dnf", Kind: RunKindCheck,
			StartedAt: base.Add(time.Duration(i) * time.Minute),
			ActorID:   "a", PlaybookSHA: "s",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	f.queue(ansible.Run{
		Status:   ansible.RunSuccess,
		ExitCode: 0,
		Stdout:   []byte(`"msg": "SW_AFFECTED_COUNT: 0"` + "\n"),
	}, nil)
	if _, err := f.runner.Check(context.Background(), f.systemID, "builtin.dnf"); err != nil {
		t.Fatalf("Check: %v", err)
	}
	rows, _ := f.store.ListRuns(f.systemID, 50)
	if len(rows) != 2 {
		t.Errorf("rows after trim = %d, want 2", len(rows))
	}
}

// blockingAnsible is a fakeAnsible variant whose Run only returns
// after release is signalled. Used to prove that the Gate serialises
// concurrent Check calls under a limit of 1.
type blockingAnsible struct {
	mu       sync.Mutex
	active   int
	maxSeen  int
	release  chan struct{}
	finished chan struct{}
}

func newBlockingAnsible() *blockingAnsible {
	return &blockingAnsible{
		release:  make(chan struct{}),
		finished: make(chan struct{}, 64),
	}
}

func (b *blockingAnsible) Run(ctx context.Context, _ ansible.Request) (ansible.Run, error) {
	b.mu.Lock()
	b.active++
	if b.active > b.maxSeen {
		b.maxSeen = b.active
	}
	b.mu.Unlock()
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	b.mu.Lock()
	b.active--
	b.mu.Unlock()
	b.finished <- struct{}{}
	return ansible.Run{Status: ansible.RunSuccess, ExitCode: 0}, nil
}

func TestRunnerGateSerialisesParallelChecks(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "gate-runner.db")
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
	sysA, err := sysStore.Create(systems.SystemInput{Name: "a", Hostname: "a.example"})
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	sysB, err := sysStore.Create(systems.SystemInput{Name: "b", Hostname: "b.example"})
	if err != nil {
		t.Fatalf("create b: %v", err)
	}
	ba := newBlockingAnsible()
	runner := &Runner{
		Registry: NewRegistry(store),
		Store:    store,
		Ansible:  ba,
		Audit:    auditStore,
		Gate:     &Gate{Limit: func() int { return 1 }},
	}
	// Fire two Checks concurrently against different systems so the
	// per-system advisory lock can't be what serialises them — only
	// the Gate's limit of 1 should.
	errs := make(chan error, 2)
	go func() {
		_, e := runner.Check(context.Background(), sysA.ID, "builtin.dnf")
		errs <- e
	}()
	go func() {
		_, e := runner.Check(context.Background(), sysB.ID, "builtin.dnf")
		errs <- e
	}()
	// Wait long enough for both to reach the gate; only one should
	// progress into ansible.Run.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ba.mu.Lock()
		active := ba.active
		ba.mu.Unlock()
		if active == 1 && runner.Gate.Waiting() == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	ba.mu.Lock()
	if ba.active != 1 {
		ba.mu.Unlock()
		t.Fatalf("ansible.active = %d, want 1 (gate must hold the second)", ba.active)
	}
	ba.mu.Unlock()
	// Release the first; the second should advance after.
	ba.release <- struct{}{}
	<-ba.finished
	ba.release <- struct{}{}
	<-ba.finished
	for i := 0; i < 2; i++ {
		if e := <-errs; e != nil {
			t.Fatalf("check %d: %v", i, e)
		}
	}
	if ba.maxSeen != 1 {
		t.Fatalf("max concurrent ansible runs = %d, want 1", ba.maxSeen)
	}
}

func TestRunnerNoTrimWhenLimitUnset(t *testing.T) {
	f := newRunnerFixture(t)
	// RunHistoryLimit left nil — retention is a no-op, every row
	// persists. The tests above already rely on this so the failure
	// here would mean the trim regressed to be unconditional.
	base := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := f.store.InsertRun(Run{
			ID: "keep-" + strconv.Itoa(i), SystemID: f.systemID,
			UpdaterID: "builtin.dnf", Kind: RunKindCheck,
			StartedAt: base.Add(time.Duration(i) * time.Minute),
			ActorID:   "a", PlaybookSHA: "s",
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	f.queue(ansible.Run{Status: ansible.RunSuccess, ExitCode: 0}, nil)
	if _, err := f.runner.Check(context.Background(), f.systemID, "builtin.dnf"); err != nil {
		t.Fatalf("Check: %v", err)
	}
	rows, _ := f.store.ListRuns(f.systemID, 50)
	if len(rows) != 4 {
		t.Errorf("rows = %d, want 4 (no trim with nil RunHistoryLimit)", len(rows))
	}
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

func TestApplyRejectsCheckOnlyUpdater(t *testing.T) {
	f := newRunnerFixture(t)
	d := sampleDef("custom.firmware")
	d.CheckOnly = true
	d.ApplyPlaybook = nil
	if _, err := f.registry.CreateCustom(d); err != nil {
		t.Fatalf("CreateCustom check-only: %v", err)
	}
	if _, err := f.runner.Apply(context.Background(), f.systemID, "custom.firmware"); !errors.Is(err, ErrCheckOnly) {
		t.Fatalf("Apply on check-only: err = %v, want ErrCheckOnly", err)
	}
	// The ansible runner must not have been invoked — we refused
	// before reaching the playbook write path.
	if len(f.ansible.calls) != 0 {
		t.Errorf("ansible was invoked for check-only apply: %+v", f.ansible.calls)
	}
	// Check on the same updater succeeds (proves the refusal is
	// scoped to Apply, not the whole updater).
	f.queue(ansible.Run{Status: ansible.RunSuccess}, nil)
	if _, err := f.runner.Check(context.Background(), f.systemID, "custom.firmware"); err != nil {
		t.Errorf("Check on check-only updater: %v", err)
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
	if !strings.Contains(string(body), "gather_facts: false") {
		t.Errorf("inspection playbook must skip facts (setup module crashes over OpenSSH-on-Windows):\n%s", body)
	}
	if !strings.Contains(string(body), "sw_is_windows | default(false) | bool") {
		t.Errorf("inspection playbook must gate windows probes on the sw_is_windows inventory var:\n%s", body)
	}
	if !strings.Contains(string(body), "/opt/homebrew/bin") {
		t.Errorf("inspection playbook must augment PATH with Homebrew locations so brew/mas resolve on macOS SSH sessions:\n%s", body)
	}
	for _, d := range defs {
		if !strings.Contains(string(body), "detect "+d.ID+" (unix)") {
			t.Errorf("inspection playbook missing unix detect task for %q:\n%s", d.ID, body)
		}
		if !strings.Contains(string(body), "detect "+d.ID+" (windows)") {
			t.Errorf("inspection playbook missing windows detect task for %q:\n%s", d.ID, body)
		}
		if !strings.Contains(string(body), "command -v "+d.DetectBinary) {
			t.Errorf("inspection playbook missing command -v for %q", d.DetectBinary)
		}
		if !strings.Contains(string(body), "where.exe "+d.DetectBinary) {
			t.Errorf("inspection playbook missing where.exe for %q", d.DetectBinary)
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

func TestParsePendingPackages(t *testing.T) {
	out := []byte(
		`ok: [h] => { "msg": "SW_PENDING_PACKAGE: kernel|6.8.0-31|6.8.0-45" }` + "\n" +
			`ok: [h] => { "msg": "SW_PENDING_PACKAGE: glibc|2.39-1|2.39-3" }` + "\n" +
			`unrelated noise` + "\n" +
			`ok: [h] => { "msg": "SW_PENDING_PACKAGE: kernel|6.8.0-31|6.8.0-45" }` + "\n" +
			`ok: [h] => { "msg": "SW_PENDING_PACKAGE: org.example||1.0" }` + "\n" +
			`ok: [h] => { "msg": "SW_PENDING_PACKAGE: legacy-name" }` + "\n",
	)
	got := parsePendingPackages(out)
	want := []PendingPackage{
		{Name: "kernel", OldVersion: "6.8.0-31", NewVersion: "6.8.0-45"},
		{Name: "glibc", OldVersion: "2.39-1", NewVersion: "2.39-3"},
		{Name: "org.example", OldVersion: "", NewVersion: "1.0"},
		{Name: "legacy-name"},
	}
	if !equalPendingPackages(got, want) {
		t.Errorf("parsePendingPackages = %v, want %v (preserve order, dedupe, accept legacy name-only)", got, want)
	}
	if got := parsePendingPackages([]byte("nothing here\n")); len(got) != 0 {
		t.Errorf("empty stdout: parsePendingPackages = %v, want []", got)
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
