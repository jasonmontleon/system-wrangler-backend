// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"system-wrangler-backend/internal/events"
	"system-wrangler-backend/internal/systems"
	"system-wrangler-backend/internal/targeting"
)

// Evaluator reconciles the live alert-instance state against the current
// metrics and reachability on each tick. It implements Prometheus-style
// "for" semantics: a breaching condition first becomes a pending
// instance, and only flips to firing once it has held for the rule's
// ForSeconds. Clearing the breach deletes the instance.
type Evaluator struct {
	Store Store
	// Querier runs metric/promql conditions. Nil disables those kinds
	// (e.g. no Prometheus configured) — reachability rules still work.
	Querier PromQuerier
	// Systems / Labels resolve a rule's target spec to candidate systems.
	Systems targeting.SystemStore
	Labels  targeting.LabelStore
	// Hub, if non-nil, receives an "alerts.changed" event whenever the
	// active set changes (instance created, fired, or resolved) so the
	// SPA refetches. The same nudge pattern as systems.changed.
	Hub *events.Hub
	// Now overrides the clock for tests. Default time.Now.
	Now func() time.Time
}

const eventAlertsChanged = "alerts.changed"

func (e *Evaluator) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

// EvaluateOnce walks every enabled rule and reconciles its instances. A
// failure on one rule is logged and does not abort the others. When any
// rule's active set changed, a single hub event is broadcast at the end.
func (e *Evaluator) EvaluateOnce(ctx context.Context) {
	rules, err := e.Store.ListEnabled()
	if err != nil {
		slog.Error("alerts: list enabled rules", "err", err)
		return
	}
	now := e.now()
	changed := false
	for _, r := range rules {
		c, err := e.evaluateRule(ctx, r, now)
		if err != nil {
			slog.Warn("alerts: evaluate rule", "err", err, "rule_id", r.ID, "name", r.Name)
			continue
		}
		changed = changed || c
	}
	if changed && e.Hub != nil {
		e.Hub.Broadcast(events.Event{Type: eventAlertsChanged})
	}
}

// evaluateRule reconciles one rule. It reports whether the active set
// changed (a membership add/remove or a pending→firing transition) so
// the caller can decide whether to broadcast.
func (e *Evaluator) evaluateRule(ctx context.Context, r Rule, now time.Time) (bool, error) {
	breaching, err := e.breachingSystems(ctx, r)
	if err != nil {
		return false, err
	}
	existing, err := e.Store.InstancesForRule(r.ID)
	if err != nil {
		return false, fmt.Errorf("load instances: %w", err)
	}
	byID := make(map[string]Instance, len(existing))
	for _, inst := range existing {
		byID[inst.SystemID] = inst
	}

	forDur := time.Duration(r.ForSeconds) * time.Second
	changed := false

	for sysID, value := range breaching {
		inst, ok := byID[sysID]
		if !ok {
			inst = Instance{
				RuleID:        r.ID,
				SystemID:      sysID,
				State:         StatePending,
				Value:         value,
				FirstBreachAt: now,
				LastEvalAt:    now,
			}
			if forDur <= 0 {
				inst.State = StateFiring
				fired := now
				inst.FiredAt = &fired
			}
			if err := e.Store.PutInstance(inst); err != nil {
				return changed, fmt.Errorf("put new instance: %w", err)
			}
			changed = true
			continue
		}
		// Existing instance: refresh value/clock, and promote to firing
		// once it has been pending long enough.
		inst.Value = value
		inst.LastEvalAt = now
		if inst.State == StatePending && now.Sub(inst.FirstBreachAt) >= forDur {
			inst.State = StateFiring
			fired := now
			inst.FiredAt = &fired
			changed = true
		}
		if err := e.Store.PutInstance(inst); err != nil {
			return changed, fmt.Errorf("update instance: %w", err)
		}
	}

	// Resolve instances whose system is no longer breaching.
	for sysID := range byID {
		if _, still := breaching[sysID]; still {
			continue
		}
		if err := e.Store.DeleteInstance(r.ID, sysID); err != nil {
			return changed, fmt.Errorf("resolve instance: %w", err)
		}
		changed = true
	}
	return changed, nil
}

// breachingSystems returns the candidate systems currently in breach of
// the rule, keyed by system id with the observed value. For unreachable
// rules the value is a 1 sentinel.
func (e *Evaluator) breachingSystems(ctx context.Context, r Rule) (map[string]float64, error) {
	candidates, err := targeting.Resolve(r.TargetKind, r.TargetValue, e.Systems, e.Labels)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	breaching := map[string]float64{}

	switch r.ConditionKind {
	case KindUnreachable:
		for _, s := range candidates {
			if s.Status == systems.StatusUnreachable {
				breaching[s.ID] = 1
			}
		}
		return breaching, nil

	case KindMetric, KindPromQL:
		if e.Querier == nil {
			slog.Debug("alerts: no querier, skipping metric rule", "rule_id", r.ID)
			return breaching, nil
		}
		expr := r.Expr
		if r.ConditionKind == KindMetric {
			expr = r.Metric.Expr()
		}
		values, err := e.Querier.InstantBySystem(ctx, expr)
		if err != nil {
			return nil, fmt.Errorf("query: %w", err)
		}
		candidateSet := make(map[string]struct{}, len(candidates))
		for _, s := range candidates {
			candidateSet[s.ID] = struct{}{}
		}
		for sysID, v := range values {
			if _, ok := candidateSet[sysID]; !ok {
				continue
			}
			if r.Comparator.Breaches(v, r.Threshold) {
				breaching[sysID] = v
			}
		}
		return breaching, nil

	default:
		return nil, fmt.Errorf("unknown condition kind %q", r.ConditionKind)
	}
}
