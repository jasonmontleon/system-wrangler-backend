// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"encoding/json"
	"fmt"

	"system-wrangler-backend/internal/labels"
	"system-wrangler-backend/internal/systems"
)

// SystemStore is the slice of systems.Store the resolver needs.
type SystemStore interface {
	List() ([]systems.System, error)
	Get(id string) (systems.System, error)
}

// LabelStore is the slice of labels.Store the resolver needs to
// evaluate selector targets in-memory.
type LabelStore interface {
	ForSystems(systemIDs []string) (map[string][]labels.Label, error)
}

// ResolveTargets returns the systems the schedule's TargetKind +
// TargetValue point at, evaluated against the current inventory at
// call time. The resolver intentionally re-resolves on every fire so
// a group's membership changes or a new system joining the inventory
// is picked up automatically. Unreachable systems are NOT pre-filtered
// here — the fan-out tally records them as failures so the operator
// sees coverage misses rather than silent skips.
func ResolveTargets(sch Schedule, systemStore SystemStore, labelStore LabelStore) ([]systems.System, error) {
	switch sch.TargetKind {
	case TargetGlobal:
		return systemStore.List()
	case TargetGroup:
		all, err := systemStore.List()
		if err != nil {
			return nil, fmt.Errorf("schedules: resolve group: %w", err)
		}
		out := make([]systems.System, 0, len(all))
		for _, s := range all {
			if s.GroupID != nil && *s.GroupID == sch.TargetValue {
				out = append(out, s)
			}
		}
		return out, nil
	case TargetSystems:
		var ids []string
		if err := json.Unmarshal([]byte(sch.TargetValue), &ids); err != nil {
			return nil, fmt.Errorf("schedules: resolve systems list: %w", err)
		}
		out := make([]systems.System, 0, len(ids))
		for _, id := range ids {
			s, err := systemStore.Get(id)
			if err != nil {
				// A pinned system going missing should not abort the
				// whole fire — record it as a failure tally upstream.
				// We surface a placeholder System so the fan-out loop
				// can record one attempt per missing id.
				out = append(out, systems.System{ID: id, Name: id, Status: systems.StatusUnreachable})
				continue
			}
			out = append(out, s)
		}
		return out, nil
	case TargetSelector:
		sel, err := labels.ParseSelector(sch.TargetValue)
		if err != nil {
			return nil, fmt.Errorf("schedules: parse selector: %w", err)
		}
		all, err := systemStore.List()
		if err != nil {
			return nil, fmt.Errorf("schedules: resolve selector: %w", err)
		}
		ids := make([]string, 0, len(all))
		for _, s := range all {
			ids = append(ids, s.ID)
		}
		byID, err := labelStore.ForSystems(ids)
		if err != nil {
			return nil, fmt.Errorf("schedules: load labels: %w", err)
		}
		out := make([]systems.System, 0, len(all))
		for _, s := range all {
			if sel.Matches(byID[s.ID]) {
				out = append(out, s)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: unsupported targetKind %q", ErrInvalid, sch.TargetKind)
	}
}
