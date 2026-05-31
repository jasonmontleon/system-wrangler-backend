// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"context"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/updaters"
)

// FanOutAction selects what to do per host: a Check sweep or an
// Apply sweep. A schedule may request both, in which case the
// orchestrator runs check then apply for each host.
type FanOutAction string

// FanOutAction values.
const (
	FanOutCheck FanOutAction = "check"
	FanOutApply FanOutAction = "apply"
)

// UpdaterRunner is the slice of *updaters.Runner the schedule fan-out
// needs. Defined as an interface so tests can inject a fake without
// pulling in ansible + ssh + vault plumbing.
type UpdaterRunner interface {
	Check(ctx context.Context, systemID, updaterID string) (updaters.RunResult, error)
	Apply(ctx context.Context, systemID, updaterID string, packages []string) (updaters.RunResult, error)
}

// UpdaterRegistry is the slice of *updaters.Registry the fan-out
// uses to enumerate the registered updater set.
type UpdaterRegistry interface {
	All() ([]updaters.Definition, error)
}

// UpdaterAvailabilityStore exposes the AvailabilityFor lookup the
// fan-out uses to filter "detected and enabled" updaters per host.
type UpdaterAvailabilityStore interface {
	AvailabilityFor(systemID string) ([]updaters.Availability, error)
}

// FanOutResult is the per-system outcome of one check or apply sweep.
type FanOutResult struct {
	SystemID  string
	Action    FanOutAction
	Attempted int
	Succeeded int
	Failed    int
	Skipped   bool
	Reason    string
}

// FanOutOnSystem runs the given action against every enabled +
// detected updater on the system, sequentially. Per-system advisory
// locking is already enforced inside updaters.Runner, so a parallel
// loop here would just deadlock the same lock — sequential is the
// honest choice. Per-updater failures are tallied in the returned
// result; the audit + updater_runs trail captures the individual
// reasons so this layer doesn't have to re-surface them.
func FanOutOnSystem(
	ctx context.Context,
	systemID string,
	action FanOutAction,
	registry UpdaterRegistry,
	ustore UpdaterAvailabilityStore,
	runner UpdaterRunner,
) FanOutResult {
	out := FanOutResult{SystemID: systemID, Action: action}
	defs, err := registry.All()
	if err != nil {
		out.Skipped = true
		out.Reason = "list updaters: " + err.Error()
		return out
	}
	avail, err := ustore.AvailabilityFor(systemID)
	if err != nil {
		out.Skipped = true
		out.Reason = "availability: " + err.Error()
		return out
	}
	byID := make(map[string]updaters.Availability, len(avail))
	for _, a := range avail {
		byID[a.UpdaterID] = a
	}
	type target struct{ id string }
	var targets []target
	for _, d := range defs {
		a, ok := byID[d.ID]
		if !ok || !a.Enabled {
			continue
		}
		if action == FanOutApply && d.CheckOnly {
			// CheckOnly updaters surface pending changes but can't
			// apply — they're a no-op for an apply sweep, not an
			// error.
			continue
		}
		targets = append(targets, target{id: d.ID})
	}
	if len(targets) == 0 {
		out.Skipped = true
		out.Reason = "no enabled updaters for this action"
		return out
	}
	out.Attempted = len(targets)
	for _, t := range targets {
		var (
			res updaters.RunResult
			err error
		)
		if action == FanOutApply {
			res, err = runner.Apply(ctx, systemID, t.id, nil)
		} else {
			res, err = runner.Check(ctx, systemID, t.id)
		}
		if err == nil && res.Status == ansible.RunSuccess {
			out.Succeeded++
		} else {
			out.Failed++
		}
	}
	return out
}
