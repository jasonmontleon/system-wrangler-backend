// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"context"
	"log/slog"
	"time"
)

// Ticker walks the schedules table on a fixed cadence and fires
// whichever rows are due. It owns no state of its own beyond the
// Orchestrator and Store references — fan-out lifecycle lives in
// the orchestrator; this type is just the wake-up loop.
type Ticker struct {
	Store        Store
	Orchestrator *Orchestrator

	// Interval is how often Run pulses the due-list. Default 1 minute.
	Interval time.Duration
	// Now overrides the clock for tests. Default time.Now.
	Now func() time.Time
}

// Run blocks until ctx is cancelled, ticking the schedule pipeline
// at Interval. The first tick fires immediately so a server start
// catches any schedules that became due while the server was down,
// without waiting a full interval first.
func (t *Ticker) Run(ctx context.Context) {
	interval := t.Interval
	if interval <= 0 {
		interval = time.Minute
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

// tick walks Due(now) and fans the fires off into goroutines so a
// slow schedule can't block the ticker. Per-schedule advisory
// locking inside Orchestrator.Fire protects against overlap; here
// we just dispatch.
func (t *Ticker) tick(ctx context.Context, now time.Time) {
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
