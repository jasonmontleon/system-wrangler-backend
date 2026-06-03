// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"errors"
	"testing"
	"time"

	"system-wrangler-backend/internal/events"
	"system-wrangler-backend/internal/labels"
	"system-wrangler-backend/internal/systems"
	"system-wrangler-backend/internal/targeting"
)

type fakeSysStore struct {
	systems []systems.System
	err     error
}

func (f fakeSysStore) List() ([]systems.System, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.systems, nil
}

func (f fakeSysStore) Get(id string) (systems.System, error) {
	if f.err != nil {
		return systems.System{}, f.err
	}
	for _, s := range f.systems {
		if s.ID == id {
			return s, nil
		}
	}
	return systems.System{}, systems.ErrNotFound
}

type fakeLabelStore struct{}

func (fakeLabelStore) ForSystems([]string) (map[string][]labels.Label, error) {
	return map[string][]labels.Label{}, nil
}

type fakeQuerier struct {
	values map[string]float64
	err    error
}

func (f fakeQuerier) InstantBySystem(context.Context, string) (map[string]float64, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.values, nil
}

func createRule(t *testing.T, st *SQLiteStore, mut func(*RuleInput)) Rule {
	t.Helper()
	in := validMetricInput()
	in.Enabled = true
	if mut != nil {
		mut(&in)
	}
	r, err := st.Create(in, "u")
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	return r
}

func TestEvaluateMetricPendingThenFiring(t *testing.T) {
	st := newTestStore(t)
	r := createRule(t, st, func(in *RuleInput) {
		in.ForSeconds = 120 // 2m
		in.Threshold = 90
		in.Comparator = GreaterThan
	})
	inv := fakeSysStore{systems: []systems.System{{ID: "a", Status: systems.StatusReachable}}}
	clock := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	ev := &Evaluator{
		Store:   st,
		Querier: fakeQuerier{values: map[string]float64{"a": 95}},
		Systems: inv,
		Labels:  fakeLabelStore{},
		Now:     func() time.Time { return clock },
	}

	ev.EvaluateOnce(context.Background())
	insts, _ := st.InstancesForRule(r.ID)
	if len(insts) != 1 || insts[0].State != StatePending {
		t.Fatalf("first eval should create one pending instance, got %+v", insts)
	}

	// Still within the for-window: stays pending.
	clock = clock.Add(time.Minute)
	ev.EvaluateOnce(context.Background())
	insts, _ = st.InstancesForRule(r.ID)
	if insts[0].State != StatePending {
		t.Errorf("should still be pending at +1m, got %s", insts[0].State)
	}

	// Past the for-window: promotes to firing.
	clock = clock.Add(2 * time.Minute)
	ev.EvaluateOnce(context.Background())
	insts, _ = st.InstancesForRule(r.ID)
	if insts[0].State != StateFiring || insts[0].FiredAt == nil {
		t.Errorf("should be firing after for-window, got %+v", insts[0])
	}
	if insts[0].Value != 95 {
		t.Errorf("value not refreshed: %v", insts[0].Value)
	}
}

func TestEvaluateForZeroFiresImmediately(t *testing.T) {
	st := newTestStore(t)
	r := createRule(t, st, func(in *RuleInput) { in.ForSeconds = 0 })
	inv := fakeSysStore{systems: []systems.System{{ID: "a", Status: systems.StatusReachable}}}
	ev := &Evaluator{
		Store:   st,
		Querier: fakeQuerier{values: map[string]float64{"a": 95}},
		Systems: inv,
		Labels:  fakeLabelStore{},
	}
	ev.EvaluateOnce(context.Background())
	insts, _ := st.InstancesForRule(r.ID)
	if len(insts) != 1 || insts[0].State != StateFiring {
		t.Fatalf("forSeconds=0 should fire immediately, got %+v", insts)
	}
}

func TestEvaluateResolvesWhenBreachClears(t *testing.T) {
	st := newTestStore(t)
	r := createRule(t, st, func(in *RuleInput) { in.ForSeconds = 0 })
	inv := fakeSysStore{systems: []systems.System{{ID: "a", Status: systems.StatusReachable}}}
	q := &fakeQuerier{values: map[string]float64{"a": 95}}
	ev := &Evaluator{Store: st, Querier: q, Systems: inv, Labels: fakeLabelStore{}}

	ev.EvaluateOnce(context.Background())
	if insts, _ := st.InstancesForRule(r.ID); len(insts) != 1 {
		t.Fatalf("expected one firing instance, got %d", len(insts))
	}
	// Value drops below threshold → resolve.
	q.values = map[string]float64{"a": 10}
	ev.EvaluateOnce(context.Background())
	if insts, _ := st.InstancesForRule(r.ID); len(insts) != 0 {
		t.Errorf("instance should resolve when breach clears, got %d", len(insts))
	}
}

func TestEvaluateUnreachableNoQuerier(t *testing.T) {
	st := newTestStore(t)
	r := createRule(t, st, func(in *RuleInput) {
		in.ConditionKind = KindUnreachable
		in.ForSeconds = 0
	})
	inv := fakeSysStore{systems: []systems.System{
		{ID: "a", Status: systems.StatusUnreachable},
		{ID: "b", Status: systems.StatusReachable},
	}}
	ev := &Evaluator{Store: st, Querier: nil, Systems: inv, Labels: fakeLabelStore{}}
	ev.EvaluateOnce(context.Background())
	insts, _ := st.InstancesForRule(r.ID)
	if len(insts) != 1 || insts[0].SystemID != "a" || insts[0].State != StateFiring {
		t.Fatalf("only unreachable system should fire, got %+v", insts)
	}
}

func TestEvaluateMetricSkippedWithoutQuerier(t *testing.T) {
	st := newTestStore(t)
	r := createRule(t, st, func(in *RuleInput) { in.ForSeconds = 0 })
	inv := fakeSysStore{systems: []systems.System{{ID: "a", Status: systems.StatusReachable}}}
	ev := &Evaluator{Store: st, Querier: nil, Systems: inv, Labels: fakeLabelStore{}}
	ev.EvaluateOnce(context.Background())
	if insts, _ := st.InstancesForRule(r.ID); len(insts) != 0 {
		t.Errorf("metric rule with no querier should produce nothing, got %d", len(insts))
	}
}

func TestEvaluateIgnoresNonCandidateSystems(t *testing.T) {
	st := newTestStore(t)
	// Rule targets group grp-1; system "b" is in another group.
	gp := "grp-1"
	createRule(t, st, func(in *RuleInput) {
		in.ForSeconds = 0
		in.TargetKind = targeting.Group
		in.TargetValue = "grp-1"
	})
	inv := fakeSysStore{systems: []systems.System{
		{ID: "a", Status: systems.StatusReachable, GroupID: &gp},
		{ID: "b", Status: systems.StatusReachable}, // ungrouped, breaches metric but out of target
	}}
	ev := &Evaluator{
		Store:   st,
		Querier: fakeQuerier{values: map[string]float64{"a": 95, "b": 99}},
		Systems: inv,
		Labels:  fakeLabelStore{},
	}
	ev.EvaluateOnce(context.Background())
	active, _ := st.ListActive()
	if len(active) != 1 || active[0].SystemID != "a" {
		t.Errorf("only in-target system should alert, got %+v", active)
	}
}

func TestEvaluateBroadcastsOnChange(t *testing.T) {
	st := newTestStore(t)
	createRule(t, st, func(in *RuleInput) { in.ForSeconds = 0 })
	inv := fakeSysStore{systems: []systems.System{{ID: "a", Status: systems.StatusReachable}}}
	hub := events.NewHub(nil)
	sub := hub.Subscribe()
	defer hub.Unsubscribe(sub)
	ev := &Evaluator{
		Store:   st,
		Querier: fakeQuerier{values: map[string]float64{"a": 95}},
		Systems: inv,
		Labels:  fakeLabelStore{},
		Hub:     hub,
	}
	ev.EvaluateOnce(context.Background())
	select {
	case e := <-sub.Ch:
		if e.Type != eventAlertsChanged {
			t.Errorf("event type = %q, want %q", e.Type, eventAlertsChanged)
		}
	default:
		t.Error("expected an alerts.changed broadcast")
	}

	// A second eval with no change should not broadcast.
	ev.EvaluateOnce(context.Background())
	select {
	case e := <-sub.Ch:
		t.Errorf("unexpected broadcast on no-change eval: %v", e)
	default:
	}
}

func TestEvaluateContinuesPastRuleError(t *testing.T) {
	st := newTestStore(t)
	// A querier error makes the metric rule fail; the evaluator should
	// log and move on rather than panic or abort.
	createRule(t, st, func(in *RuleInput) { in.ForSeconds = 0 })
	inv := fakeSysStore{systems: []systems.System{{ID: "a", Status: systems.StatusReachable}}}
	ev := &Evaluator{
		Store:   st,
		Querier: fakeQuerier{err: errors.New("prometheus down")},
		Systems: inv,
		Labels:  fakeLabelStore{},
	}
	ev.EvaluateOnce(context.Background()) // must not panic
}

type recordingSink struct{ batches [][]Transition }

func (s *recordingSink) Emit(_ context.Context, ts []Transition) {
	s.batches = append(s.batches, ts)
}

func TestEvaluatorEmitsFiredThenResolved(t *testing.T) {
	st := newTestStore(t)
	createRule(t, st, func(in *RuleInput) { in.ForSeconds = 0 })
	inv := fakeSysStore{systems: []systems.System{{ID: "a", Status: systems.StatusReachable}}}
	q := &fakeQuerier{values: map[string]float64{"a": 95}}
	sink := &recordingSink{}
	ev := &Evaluator{Store: st, Querier: q, Systems: inv, Labels: fakeLabelStore{}, Sink: sink}

	ev.EvaluateOnce(context.Background())
	if len(sink.batches) != 1 || len(sink.batches[0]) != 1 || sink.batches[0][0].Kind != TransitionFired {
		t.Fatalf("expected one fired transition, got %+v", sink.batches)
	}
	if sink.batches[0][0].SystemID != "a" || sink.batches[0][0].Value != 95 {
		t.Errorf("fired transition fields wrong: %+v", sink.batches[0][0])
	}

	// Breach clears → a resolved transition for the firing instance.
	q.values = map[string]float64{}
	ev.EvaluateOnce(context.Background())
	last := sink.batches[len(sink.batches)-1]
	if len(last) != 1 || last[0].Kind != TransitionResolved || last[0].SystemID != "a" {
		t.Errorf("expected resolved transition, got %+v", last)
	}
}

func TestEvaluatorPendingClearEmitsNoTransition(t *testing.T) {
	st := newTestStore(t)
	// for=120s so the breach stays pending; clearing it should not emit a
	// resolved transition (nobody was ever notified).
	createRule(t, st, func(in *RuleInput) { in.ForSeconds = 120 })
	inv := fakeSysStore{systems: []systems.System{{ID: "a", Status: systems.StatusReachable}}}
	q := &fakeQuerier{values: map[string]float64{"a": 95}}
	sink := &recordingSink{}
	ev := &Evaluator{Store: st, Querier: q, Systems: inv, Labels: fakeLabelStore{}, Sink: sink}

	ev.EvaluateOnce(context.Background()) // pending, no transition
	q.values = map[string]float64{}
	ev.EvaluateOnce(context.Background()) // clears while pending
	for _, b := range sink.batches {
		if len(b) != 0 {
			t.Errorf("pending lifecycle should emit no transitions, got %+v", b)
		}
	}
}

func TestEvaluateListEnabledError(_ *testing.T) {
	ev := &Evaluator{Store: errStore{}, Systems: fakeSysStore{}, Labels: fakeLabelStore{}}
	ev.EvaluateOnce(context.Background()) // must not panic on store error
}

// errStore fails ListEnabled to exercise the top-level error path.
type errStore struct{ Store }

func (errStore) ListEnabled() ([]Rule, error) { return nil, errors.New("db dead") }
