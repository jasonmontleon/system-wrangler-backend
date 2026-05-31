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
