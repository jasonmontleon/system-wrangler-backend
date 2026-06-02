// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"context"
	"log/slog"
	"time"
)

// DefaultMisfireGrace bounds how late a schedule may fire. A run whose
// scheduled time slipped further into the past than this — almost
// always because the server was down across the fire time — is treated
// as missed: it is rescheduled to its next future occurrence instead of
// firing. This is what stops a fleet-wide spike of catch-up runs the
// moment the server comes back after a planned or unplanned outage. It
// is generous enough to absorb tick jitter and a quick redeploy (which
// should still fire) while skipping the long outages that pile work up.
const DefaultMisfireGrace = 2 * time.Minute

// Ticker walks the schedules table on a fixed cadence and fires
// whichever rows are due. It owns no state of its own beyond the
// Orchestrator and Store references — fan-out lifecycle lives in
// the orchestrator; this type is just the wake-up loop.
type Ticker struct {
	Store        Store
	Orchestrator *Orchestrator

	// Interval is how often Run pulses the due-list. Default 1 minute.
	Interval time.Duration
	// MisfireGrace bounds how late a due schedule may still fire before
	// it is treated as missed and rescheduled without running. Default
	// DefaultMisfireGrace.
	MisfireGrace time.Duration
	// Now overrides the clock for tests. Default time.Now.
	Now func() time.Time
}

// Run blocks until ctx is cancelled, ticking the schedule pipeline
// at Interval. The first tick fires immediately so a server start
// picks up anything due right now without waiting a full interval —
// but schedules whose fire time was missed while the server was down
// are rescheduled rather than run (see tick), so a restart never
// triggers a catch-up spike.
func (t *Ticker) Run(ctx context.Context) {
	interval := t.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	if t.MisfireGrace <= 0 {
		t.MisfireGrace = DefaultMisfireGrace
	}
	now := t.Now
	if now == nil {
		now = time.Now
	}
	t.tick(ctx, now())
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case at := <-tk.C:
			t.tick(ctx, at)
		}
	}
}

// tick first reschedules any schedules missed while the server was
// down (so they don't all fire at once on restart), then walks
// Due(now) and fans the fires off into goroutines so a slow schedule
// can't block the ticker. Per-schedule advisory locking inside
// Orchestrator.Fire protects against overlap; here we just dispatch.
func (t *Ticker) tick(ctx context.Context, now time.Time) {
	grace := t.MisfireGrace
	if grace <= 0 {
		grace = DefaultMisfireGrace
	}
	// Reschedule missed runs before reading the due-list: any schedule
	// whose fire time slipped past the grace window is pushed to its
	// next future occurrence here, so Due(now) below returns only the
	// runs that are legitimately due within the window.
	if missed, err := t.Store.ReconcileMissed(now, grace); err != nil {
		slog.Error("schedules: ticker reconcile missed", "err", err)
	} else {
		for _, sch := range missed {
			var was string
			if sch.NextRunAt != nil {
				was = sch.NextRunAt.UTC().Format(time.RFC3339)
			}
			slog.Warn("schedules: skipping missed run, rescheduled to next occurrence",
				"schedule_id", sch.ID, "name", sch.Name, "missed_run_at", was)
		}
	}

	due, err := t.Store.Due(now)
	if err != nil {
		slog.Error("schedules: ticker due", "err", err)
		return
	}
	for _, sch := range due {
		go func(sch Schedule) {
			if _, err := t.Orchestrator.Fire(ctx, sch); err != nil {
				slog.Error("schedules: fire", "err", err, "schedule_id", sch.ID)
			}
		}(sch)
	}
}
