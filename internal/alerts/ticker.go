// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"time"
)

// DefaultEvalInterval is the fallback cadence at which the Ticker
// evaluates rules when no interval is configured. One minute matches the
// schedules ticker and Prometheus's default scrape granularity — there's
// no value in evaluating thresholds faster than the data refreshes.
const DefaultEvalInterval = time.Minute

// Ticker drives the Evaluator on a fixed cadence. It owns no state
// beyond the Evaluator reference; the firing-state lifecycle lives in
// the evaluator. The first tick fires immediately so a server start
// picks up current breaches without waiting a full interval.
type Ticker struct {
	Evaluator *Evaluator

	// Interval is the fallback cadence used when IntervalFn is nil.
	// Defaults to DefaultEvalInterval when unset.
	Interval time.Duration
	// IntervalFn, when non-nil, is consulted each tick for the live
	// interval so a settings change takes effect on the next cycle
	// without a restart. Returning <= 0 falls back to Interval.
	IntervalFn func() time.Duration
}

// Run blocks until ctx is cancelled, evaluating rules at the resolved
// interval. Because IntervalFn may change between ticks, the loop uses a
// timer reset each cycle rather than a fixed time.Ticker.
func (t *Ticker) Run(ctx context.Context) {
	t.Evaluator.EvaluateOnce(ctx)
	timer := time.NewTimer(t.resolveInterval())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			t.Evaluator.EvaluateOnce(ctx)
			timer.Reset(t.resolveInterval())
		}
	}
}

func (t *Ticker) resolveInterval() time.Duration {
	if t.IntervalFn != nil {
		if d := t.IntervalFn(); d > 0 {
			return d
		}
	}
	if t.Interval > 0 {
		return t.Interval
	}
	return DefaultEvalInterval
}
