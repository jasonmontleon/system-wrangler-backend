// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/systems"
	"system-wrangler-backend/internal/updaters"
)

func newFiringOrchestrator(t *testing.T) (*Orchestrator, *SQLiteStore) {
	t.Helper()
	store, _ := newStore(t)
	o := &Orchestrator{
		Store: store,
	}
	return o, store
}

// rosySetup wires the orchestrator with a 1-system inventory, one
// enabled detected updater, an always-success runner. Useful as a
// starting point for happy-path tests.
func rosySetup(t *testing.T) (*Orchestrator, Schedule) {
	t.Helper()
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{systems: []systems.System{{ID: "s1", Name: "alpha"}}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	o.Updaters = fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	o.Runner = &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) { return ok() },
		apply: func(string, string, []string) (updaters.RunResult, error) { return ok() },
	}
	in := validInput()
	in.RunCheck = true
	sch, err := store.Create(in, "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return o, sch
}

func TestFireRecordsSuccessRunForOneHostHappyPath(t *testing.T) {
	o, sch := rosySetup(t)
	run, err := o.Fire(context.Background(), sch)
	if err != nil {
		t.Fatalf("Fire: %v", err)
	}
	if run.Status != StatusSuccess {
		t.Errorf("Status = %q", run.Status)
	}
	if run.TargetsAttempted != 1 || run.TargetsSucceeded != 1 || run.TargetsFailed != 0 {
		t.Errorf("counts: %+v", run)
	}
}

func TestFireRecordsPartialWhenSomeHostsFail(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{systems: []systems.System{
		{ID: "ok"},
		{ID: "broken"},
	}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	o.Updaters = fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	o.Runner = &fakeRunner{
		check: func(sysID, _ string) (updaters.RunResult, error) {
			if sysID == "broken" {
				return fail()
			}
			return ok()
		},
	}
	in := validInput() // global, runCheck=true
	sch, _ := store.Create(in, "user-1")
	run, _ := o.Fire(context.Background(), sch)
	if run.Status != StatusPartial {
		t.Errorf("Status = %q, want partial", run.Status)
	}
	if run.TargetsSucceeded != 1 || run.TargetsFailed != 1 {
		t.Errorf("counts: %+v", run)
	}
}

func TestFireRecordsFailedWhenEveryHostFails(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{systems: []systems.System{{ID: "a"}, {ID: "b"}}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	o.Updaters = fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	o.Runner = &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) { return fail() },
	}
	sch, _ := store.Create(validInput(), "user-1")
	run, _ := o.Fire(context.Background(), sch)
	if run.Status != StatusFailed {
		t.Errorf("Status = %q, want failed", run.Status)
	}
}

func TestFireWithZeroTargetsRecordsSuccessAndAdvances(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{systems: []systems.System{}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{}}
	o.Updaters = fakeAvailStore{}
	sch, _ := store.Create(validInput(), "user-1")
	run, err := o.Fire(context.Background(), sch)
	if err != nil {
		t.Fatalf("Fire: %v", err)
	}
	if run.TargetsAttempted != 0 {
		t.Errorf("attempted = %d", run.TargetsAttempted)
	}
	// Empty target sets aren't failures — they're a no-op.
	if run.Status != StatusSuccess {
		t.Errorf("Status = %q", run.Status)
	}
}

func TestFireResolveTargetsErrorIsRecordedAsFailure(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	// Selector that errors out at resolve time.
	in := validInput()
	in.TargetKind = TargetSelector
	in.TargetValue = "env=prod"
	sch, _ := store.Create(in, "user-1")
	o.Systems = fakeSysStore{err: errors.New("db down")}
	o.Labels = fakeLabelStore{}
	run, err := o.Fire(context.Background(), sch)
	if err != nil {
		t.Fatalf("Fire: %v", err)
	}
	if run.Status != StatusFailed {
		t.Errorf("Status = %q, want failed", run.Status)
	}
}

func TestFireConcurrentForSameScheduleSkipsSecond(t *testing.T) {
	o, sch := rosySetup(t)
	// Throttle the runner so the second caller can grab the lock-busy
	// branch deterministically.
	gate := make(chan struct{})
	o.Runner = &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) {
			<-gate
			return ok()
		},
	}
	var wg sync.WaitGroup
	var first, second ScheduleRun
	wg.Add(2)
	go func() {
		defer wg.Done()
		first, _ = o.Fire(context.Background(), sch)
	}()
	// Give the first goroutine a chance to take the lock before the
	// second tries.
	time.Sleep(20 * time.Millisecond)
	go func() {
		defer wg.Done()
		second, _ = o.Fire(context.Background(), sch)
	}()
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	// One of them carries TargetsAttempted=1, the other is the
	// skipped zero-value.
	if (first.TargetsAttempted == 0) == (second.TargetsAttempted == 0) {
		t.Errorf("Expected exactly one to have run; first=%+v second=%+v", first, second)
	}
}

func TestFireRunsCheckThenApplyWhenBothRequested(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{systems: []systems.System{{ID: "s1"}}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	o.Updaters = fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	var checked, applied int
	o.Runner = &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) { checked++; return ok() },
		apply: func(string, string, []string) (updaters.RunResult, error) { applied++; return ok() },
	}
	in := validInput()
	in.RunCheck = true
	in.RunApply = true
	sch, _ := store.Create(in, "user-1")
	if _, err := o.Fire(context.Background(), sch); err != nil {
		t.Fatalf("Fire: %v", err)
	}
	if checked != 1 || applied != 1 {
		t.Errorf("checked=%d applied=%d, want 1+1", checked, applied)
	}
}

func TestFireSkipsApplyWhenCheckFailed(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{systems: []systems.System{{ID: "s1"}}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	o.Updaters = fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	var applied int
	o.Runner = &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) { return fail() },
		apply: func(string, string, []string) (updaters.RunResult, error) { applied++; return ok() },
	}
	in := validInput()
	in.RunCheck = true
	in.RunApply = true
	sch, _ := store.Create(in, "user-1")
	if _, err := o.Fire(context.Background(), sch); err != nil {
		t.Fatalf("Fire: %v", err)
	}
	if applied != 0 {
		t.Errorf("apply must not fire after a failed check, got applied=%d", applied)
	}
}

func TestFireRebootsAfterSuccessfulApplyWhenFlagSet(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	rebootAt := time.Now()
	o.Systems = rebootSysStore{sys: systems.System{
		ID: "s1", RebootRequiredAt: &rebootAt,
	}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	o.Updaters = fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	o.Runner = &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) { return ok() },
		apply: func(string, string, []string) (updaters.RunResult, error) { return ok() },
	}
	clearer := &fakeClearer{}
	o.Clearer = clearer
	o.Ansible = &fakeAnsible{status: ansible.RunSuccess}
	in := validInput()
	in.RunCheck = false
	in.RunApply = true
	in.RebootAfterApply = true
	sch, _ := store.Create(in, "user-1")
	run, err := o.Fire(context.Background(), sch)
	if err != nil {
		t.Fatalf("Fire: %v", err)
	}
	if !clearer.called {
		t.Error("ClearRebootRequired must fire after successful reboot")
	}
	if run.Status != StatusSuccess {
		t.Errorf("Status = %q", run.Status)
	}
}

func TestFireDispatchesHostsInParallel(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{systems: []systems.System{
		{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"},
	}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	o.Updaters = fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	// Each Check blocks until the gate is released. If the
	// orchestrator dispatched sequentially the gate would never
	// reach the expected concurrent-callers count.
	var inFlight, peak atomic.Int32
	release := make(chan struct{})
	o.Runner = &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) {
			now := inFlight.Add(1)
			for {
				p := peak.Load()
				if now <= p || peak.CompareAndSwap(p, now) {
					break
				}
			}
			<-release
			inFlight.Add(-1)
			return ok()
		},
	}
	sch, _ := store.Create(validInput(), "user-1")
	done := make(chan struct{})
	go func() {
		_, _ = o.Fire(context.Background(), sch)
		close(done)
	}()
	// Wait for the orchestrator to fan out at least two callers.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && peak.Load() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	<-done
	if peak.Load() < 2 {
		t.Errorf("orchestrator must dispatch at least 2 hosts concurrently, peak = %d", peak.Load())
	}
}

func TestFireRecordRunStartFailureSurfacesError(t *testing.T) {
	// Close the DB so RecordRunStart fails.
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{systems: []systems.System{{ID: "s1"}}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{}}
	o.Updaters = fakeAvailStore{}
	sch, _ := store.Create(validInput(), "user-1")
	// Close the db inside store to force RecordRunStart to fail.
	if err := store.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := o.Fire(context.Background(), sch); err == nil {
		t.Error("expected error from RecordRunStart")
	}
}
