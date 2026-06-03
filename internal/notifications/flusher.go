// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"context"
	"log/slog"
	"time"

	"system-wrangler-backend/internal/alerts"
)

// DefaultFlushInterval is how often the Flusher checks whether quiet hours
// have ended. Minute granularity matches the quiet-window resolution.
const DefaultFlushInterval = time.Minute

// FlushPending releases deferred deliveries once the clock is outside
// every quiet window. Pending transitions are grouped by (rule, system);
// a group that both fired and resolved while deferred is dropped (the
// episode came and went — nothing to send), otherwise its last transition
// is delivered to the rule's current routed, enabled channels. Processed
// rows are removed whether delivered or dropped.
func (d *Dispatcher) FlushPending(_ context.Context) {
	policy, err := d.Store.GetPolicy()
	if err != nil {
		slog.Error("notifications: flush get policy", "err", err)
		return
	}
	if policy.InQuietHours(d.now()) {
		return
	}
	pending, err := d.Store.ListPending()
	if err != nil {
		slog.Error("notifications: flush list pending", "err", err)
		return
	}
	if len(pending) == 0 {
		return
	}
	enabled, err := d.Store.ListEnabled()
	if err != nil {
		slog.Error("notifications: flush list enabled", "err", err)
		return
	}
	byID := indexByID(enabled)

	type key struct{ rule, system string }
	groups := map[key][]PendingDelivery{}
	var order []key
	for _, p := range pending {
		k := key{p.RuleID, p.SystemID}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], p)
	}

	routingCache := make(map[string]Routing)
	processed := make([]string, 0, len(pending))
	for _, k := range order {
		items := groups[k]
		for _, p := range items {
			processed = append(processed, p.ID)
		}
		if collapses(items) {
			continue
		}
		last := items[len(items)-1]
		for _, c := range d.routedTargets(last.RuleID, enabled, byID, routingCache) {
			go d.deliver(c, last.Message) //nolint:gosec // detached on purpose, like Emit
		}
	}
	if err := d.Store.DeletePending(processed); err != nil {
		slog.Error("notifications: flush delete pending", "err", err)
	}
}

// collapses reports whether a (rule, system) group both fired and resolved
// while deferred, meaning the whole episode elapsed during quiet hours and
// nothing should be sent.
func collapses(items []PendingDelivery) bool {
	var fired, resolved bool
	for _, p := range items {
		switch p.Kind {
		case string(alerts.TransitionFired):
			fired = true
		case string(alerts.TransitionResolved):
			resolved = true
		}
	}
	return fired && resolved
}

// Flusher drives FlushPending on a fixed cadence, mirroring alerts.Ticker.
// The first tick fires immediately so a restart releases anything that came
// due while the server was down.
type Flusher struct {
	Dispatcher *Dispatcher
	// Interval is the check cadence; defaults to DefaultFlushInterval.
	Interval time.Duration
}

// Run blocks until ctx is cancelled, flushing due deliveries each tick.
func (f *Flusher) Run(ctx context.Context) {
	f.Dispatcher.FlushPending(ctx)
	timer := time.NewTimer(f.interval())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			f.Dispatcher.FlushPending(ctx)
			timer.Reset(f.interval())
		}
	}
}

func (f *Flusher) interval() time.Duration {
	if f.Interval > 0 {
		return f.Interval
	}
	return DefaultFlushInterval
}
