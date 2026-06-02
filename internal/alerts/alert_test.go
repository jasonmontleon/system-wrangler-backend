// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"errors"
	"math"
	"strings"
	"testing"

	"system-wrangler-backend/internal/targeting"
)

func validMetricInput() RuleInput {
	return RuleInput{
		Name:          "high memory",
		ConditionKind: KindMetric,
		Metric:        MetricMemUsedPct,
		Comparator:    GreaterThan,
		Threshold:     90,
		ForSeconds:    300,
		Severity:      SeverityWarning,
		TargetKind:    targeting.Global,
	}
}

func TestValidateMetricRuleOK(t *testing.T) {
	in := validMetricInput()
	if err := in.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateDefaultsSeverity(t *testing.T) {
	in := validMetricInput()
	in.Severity = ""
	if err := in.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if in.Severity != SeverityWarning {
		t.Errorf("severity = %q, want warning default", in.Severity)
	}
}

func TestValidatePromQLRuleOK(t *testing.T) {
	in := validMetricInput()
	in.ConditionKind = KindPromQL
	in.Metric = MetricMemUsedPct // should be cleared
	in.Expr = "node_load1 by (system_id)"
	if err := in.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if in.Metric != "" {
		t.Errorf("metric should be cleared for promql kind, got %q", in.Metric)
	}
}

func TestValidateUnreachableClearsMetricFields(t *testing.T) {
	in := validMetricInput()
	in.ConditionKind = KindUnreachable
	in.Expr = "garbage"
	in.Threshold = 5
	if err := in.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if in.Metric != "" || in.Expr != "" || in.Comparator != "" || in.Threshold != 0 {
		t.Errorf("unreachable should clear metric/expr/comparator/threshold, got %+v", in)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RuleInput)
	}{
		{"empty name", func(in *RuleInput) { in.Name = "   " }},
		{"long name", func(in *RuleInput) { in.Name = strings.Repeat("x", maxNameLen+1) }},
		{"long description", func(in *RuleInput) { in.Description = strings.Repeat("x", maxDescLen+1) }},
		{"bad severity", func(in *RuleInput) { in.Severity = "panic" }},
		{"negative for", func(in *RuleInput) { in.ForSeconds = -1 }},
		{"huge for", func(in *RuleInput) { in.ForSeconds = maxForSecond + 1 }},
		{"unknown metric", func(in *RuleInput) { in.Metric = "cpu_temperature" }},
		{"bad comparator", func(in *RuleInput) { in.Comparator = "near" }},
		{"NaN threshold", func(in *RuleInput) { in.Threshold = math.NaN() }},
		{"Inf threshold", func(in *RuleInput) { in.Threshold = math.Inf(1) }},
		{"promql empty expr", func(in *RuleInput) { in.ConditionKind = KindPromQL; in.Metric = ""; in.Expr = "" }},
		{"promql long expr", func(in *RuleInput) {
			in.ConditionKind = KindPromQL
			in.Metric = ""
			in.Expr = strings.Repeat("x", maxExprLen+1)
		}},
		{"unknown kind", func(in *RuleInput) { in.ConditionKind = "smoke" }},
		{"bad target", func(in *RuleInput) { in.TargetKind = targeting.Group; in.TargetValue = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validMetricInput()
			tt.mutate(&in)
			err := in.Validate()
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("expected ErrInvalid, got %v", err)
			}
		})
	}
}

func TestComparatorBreaches(t *testing.T) {
	tests := []struct {
		c          Comparator
		value, thr float64
		want       bool
	}{
		{GreaterThan, 91, 90, true},
		{GreaterThan, 90, 90, false},
		{GreaterThanEqual, 90, 90, true},
		{LessThan, 5, 10, true},
		{LessThan, 10, 10, false},
		{LessThanEqual, 10, 10, true},
		{Comparator("bogus"), 1, 0, false},
	}
	for _, tt := range tests {
		if got := tt.c.Breaches(tt.value, tt.thr); got != tt.want {
			t.Errorf("%s.Breaches(%v,%v) = %v, want %v", tt.c, tt.value, tt.thr, got, tt.want)
		}
	}
}

func TestComparatorIsValid(t *testing.T) {
	for _, c := range []Comparator{GreaterThan, GreaterThanEqual, LessThan, LessThanEqual} {
		if !c.IsValid() {
			t.Errorf("%q should be valid", c)
		}
	}
	if Comparator("eq").IsValid() {
		t.Error("eq should be invalid")
	}
}

func TestSeverityIsValid(t *testing.T) {
	for _, s := range []Severity{SeverityInfo, SeverityWarning, SeverityCritical} {
		if !s.IsValid() {
			t.Errorf("%q should be valid", s)
		}
	}
	if Severity("emergency").IsValid() {
		t.Error("emergency should be invalid")
	}
}

func TestNewUUIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := newUUID()
		if len(id) != 36 {
			t.Fatalf("bad uuid length: %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate uuid: %q", id)
		}
		seen[id] = true
	}
}
