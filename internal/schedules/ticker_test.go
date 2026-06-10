// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"system-wrangler-backend/internal/systems"
	"system-wrangler-backend/internal/updaters"
)

func TestTickerFireContext(t *testing.T) {
	loop := context.Background()
	// Unset FireCtx falls back to the loop context so tests and any
	// caller that doesn't decouple keep their old behavior.
	tk := &Ticker{}
	if got := tk.fireContext(loop); got != loop {
		t.Errorf("nil FireCtx: got %v, want the loop ctx", got)
	}
	// A set FireCtx is used for fires, decoupling them from the loop ctx
	// that a shutdown signal cancels.
	type k struct{}
	fireCtx := context.WithValue(context.Background(), k{}, "fire")
	tk.FireCtx = fireCtx
	if got := tk.fireContext(loop); got != fireCtx {
		t.Errorf("set FireCtx: got %v, want the FireCtx", got)
	}
}

func TestTickerFiresDueSchedulesOnTick(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{systems: []systems.System{{ID: "s1"}}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	o.Updaters = fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	var fired atomic.Int32
	o.Runner = &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) {
			fired.Add(1)
			return ok()
		},
	}
	sch, err := store.Create(validInput(), "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sch.NextRunAt == nil {
		t.Fatal("expected next_run_at set after create")
	}
	// Lie about the wall clock so the ticker sees the schedule as due.
	atNextRun := *sch.NextRunAt
	tk := &Ticker{
		Store:        store,
		Orchestrator: o,
		Interval:     50 * time.Millisecond,
		Now:          func() time.Time { return atNextRun.Add(time.Second) },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	tk.Run(ctx)
	if fired.Load() < 1 {
		t.Errorf("expected at least one fire, got %d", fired.Load())
	}
}

func TestTickerReschedulesMissedRunsInsteadOfFiring(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{systems: []systems.System{{ID: "s1"}}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	o.Updaters = fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	var fired atomic.Int32
	o.Runner = &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) {
			fired.Add(1)
			return ok()
		},
	}
	sch, err := store.Create(validInput(), "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Pretend the server was down for an hour past the fire time — far
	// beyond the grace window, so this is a missed run, not a late one.
	staleNow := sch.NextRunAt.Add(time.Hour)
	tk := &Ticker{
		Store:        store,
		Orchestrator: o,
		Interval:     50 * time.Millisecond,
		MisfireGrace: 2 * time.Minute,
		Now:          func() time.Time { return staleNow },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	tk.Run(ctx)

	if fired.Load() != 0 {
		t.Errorf("missed schedule fired %d times, want 0 (no catch-up spike)", fired.Load())
	}
	reloaded, err := store.Get(sch.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if reloaded.NextRunAt == nil || !reloaded.NextRunAt.After(staleNow) {
		t.Errorf("missed schedule NextRunAt = %v, want rescheduled past %v", reloaded.NextRunAt, staleNow)
	}
	// It never ran, so last_run_at stays unset.
	if reloaded.LastRunAt != nil {
		t.Errorf("missed schedule stamped last_run_at = %v, want nil", reloaded.LastRunAt)
	}
}

func TestTickerGraceFnOverridesMisfireField(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{systems: []systems.System{{ID: "s1"}}}
	o.Registry = fakeRegistry{defs: []updaters.Definition{{ID: "dnf"}}}
	o.Updaters = fakeAvailStore{rows: []updaters.Availability{{UpdaterID: "dnf", Enabled: true}}}
	var fired atomic.Int32
	o.Runner = &fakeRunner{
		check: func(string, string) (updaters.RunResult, error) {
			fired.Add(1)
			return ok()
		},
	}
	sch, err := store.Create(validInput(), "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// The fire time is 90s in the past. The field would treat that as
	// within grace (2m default), but GraceFn returns a tight 30s window
	// that takes precedence — so this is a missed run and must not fire.
	staleNow := sch.NextRunAt.Add(90 * time.Second)
	tk := &Ticker{
		Store:        store,
		Orchestrator: o,
		Interval:     50 * time.Millisecond,
		MisfireGrace: 2 * time.Minute,
		GraceFn:      func() time.Duration { return 30 * time.Second },
		Now:          func() time.Time { return staleNow },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	tk.Run(ctx)

	if fired.Load() != 0 {
		t.Errorf("GraceFn window should treat the run as missed, fired=%d", fired.Load())
	}
	reloaded, err := store.Get(sch.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if reloaded.NextRunAt == nil || !reloaded.NextRunAt.After(staleNow) {
		t.Errorf("missed schedule NextRunAt = %v, want rescheduled past %v", reloaded.NextRunAt, staleNow)
	}
}

func TestTickerDoesNothingWhenNothingDue(t *testing.T) {
	o, store := newFiringOrchestrator(t)
	o.Systems = fakeSysStore{}
	o.Registry = fakeRegistry{}
	o.Updaters = fakeAvailStore{}
	// Default schedule fires at 03:00 UTC — likely in the future
	// during a test run that is not at midnight.
	_, _ = store.Create(validInput(), "user-1")
	// Force the schedule's NextRunAt far into the future.
	if _, err := store.SetEnabled("__none__", false); err == nil {
		t.Skip("setup invariant changed")
	}
	tk := &Ticker{
		Store:        store,
		Orchestrator: o,
		Interval:     20 * time.Millisecond,
		// Pin "now" to 1970 so no schedule is due.
		Now: func() time.Time { return time.Unix(0, 0) },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	tk.Run(ctx)
}

func TestTickerCancelsCleanly(t *testing.T) {
	store, _ := newStore(t)
	o := &Orchestrator{Store: store}
	tk := &Ticker{
		Store:        store,
		Orchestrator: o,
		Interval:     10 * time.Millisecond,
		Now:          func() time.Time { return time.Unix(0, 0) },
	}
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		tk.Run(ctx)
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ticker did not stop after cancel")
	}
}
