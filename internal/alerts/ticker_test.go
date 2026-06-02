// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"system-wrangler-backend/internal/systems"
)

func TestTickerFiresImmediatelyThenInterval(t *testing.T) {
	st := newTestStore(t)
	createRule(t, st, func(in *RuleInput) { in.ForSeconds = 0 })
	inv := fakeSysStore{systems: []systems.System{{ID: "a", Status: systems.StatusReachable}}}
	ev := &Evaluator{
		Store:   st,
		Querier: fakeQuerier{values: map[string]float64{"a": 95}},
		Systems: inv,
		Labels:  fakeLabelStore{},
	}
	tk := &Ticker{Evaluator: ev, Interval: 20 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tk.Run(ctx); close(done) }()

	// First tick is immediate; poll until the instance appears.
	deadline := time.After(2 * time.Second)
	for {
		if insts, _ := st.InstancesForRule(firstRuleID(t, st)); len(insts) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("ticker did not evaluate within deadline")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func TestResolveInterval(t *testing.T) {
	tests := []struct {
		name string
		tk   Ticker
		want time.Duration
	}{
		{"default", Ticker{}, DefaultEvalInterval},
		{"fixed interval", Ticker{Interval: 5 * time.Second}, 5 * time.Second},
		{"fn wins", Ticker{Interval: 5 * time.Second, IntervalFn: func() time.Duration { return 2 * time.Second }}, 2 * time.Second},
		{"fn non-positive falls back", Ticker{Interval: 5 * time.Second, IntervalFn: func() time.Duration { return 0 }}, 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tk.resolveInterval(); got != tt.want {
				t.Errorf("resolveInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTickerHonorsIntervalFn(t *testing.T) {
	var calls atomic.Int32
	st := newTestStore(t)
	inv := fakeSysStore{}
	ev := &Evaluator{Store: st, Systems: inv, Labels: fakeLabelStore{}}
	tk := &Ticker{
		Evaluator:  ev,
		IntervalFn: func() time.Duration { calls.Add(1); return 15 * time.Millisecond },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	tk.Run(ctx)
	if calls.Load() < 2 {
		t.Errorf("IntervalFn should be consulted across multiple ticks, got %d calls", calls.Load())
	}
}

func firstRuleID(t *testing.T, st *SQLiteStore) string {
	t.Helper()
	rules, err := st.List()
	if err != nil || len(rules) == 0 {
		t.Fatalf("no rules: %v", err)
	}
	return rules[0].ID
}
