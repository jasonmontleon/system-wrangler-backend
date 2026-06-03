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

// FlushPending releases deferred deliveries whose governing quiet window
// has ended. Pending transitions are grouped by (user, rule, system); a
// group is left in place while its owner's policy is still in quiet hours
// (the global policy for shared rows, the user's own policy for personal
// rows). A group that both fired and resolved while deferred is dropped
// (the episode came and went); otherwise its last transition is delivered
// — to the rule's current routed shared channels, or to the user's enabled
// personal channels. Processed rows are removed whether delivered or
// dropped.
func (d *Dispatcher) FlushPending(_ context.Context) {
	pending, err := d.Store.ListPending()
	if err != nil {
		slog.Error("notifications: flush list pending", "err", err)
		return
	}
	if len(pending) == 0 {
		return
	}
	now := d.now()

	type key struct{ user, rule, system string }
	groups := map[key][]PendingDelivery{}
	var order []key
	for _, p := range pending {
		k := key{p.UserID, p.RuleID, p.SystemID}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], p)
	}

	// Lazily loaded shared channel set; per-owner policy + user channel
	// caches reused across groups.
	var enabled []Channel
	var byID map[string]Channel
	sharedLoaded := false
	routingCache := make(map[string]Routing)
	uc := newUserDispatch()
	policyCache := map[string]Policy{}
	governing := func(uid string) Policy {
		if p, ok := policyCache[uid]; ok {
			return p
		}
		var p Policy
		var perr error
		if uid == "" {
			p, perr = d.Store.GetPolicy()
		} else {
			p, perr = d.Store.GetUserPolicy(uid)
		}
		if perr != nil {
			slog.Error("notifications: flush get policy", "err", perr, "user_id", uid)
			p = DefaultPolicy()
		}
		policyCache[uid] = p
		return p
	}

	processed := make([]string, 0, len(pending))
	for _, k := range order {
		// Still quiet for this owner — leave the whole group pending.
		if governing(k.user).InQuietHours(now) {
			continue
		}
		items := groups[k]
		for _, p := range items {
			processed = append(processed, p.ID)
		}
		if collapses(items) {
			continue
		}
		last := items[len(items)-1]
		var targets []Channel
		if k.user == "" {
			if !sharedLoaded {
				if enabled, err = d.Store.ListEnabled(); err != nil {
					slog.Error("notifications: flush list enabled", "err", err)
					enabled = nil
				}
				byID = indexByID(enabled)
				sharedLoaded = true
			}
			targets = d.routedTargets(last.RuleID, enabled, byID, routingCache)
		} else {
			targets = uc.channels(d, k.user)
		}
		d.fanOut(targets, last.Message, k.user)
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
