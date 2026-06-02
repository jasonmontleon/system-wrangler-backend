// SPDX-License-Identifier: Apache-2.0

// Package alerts evaluates operator-defined threshold rules against the
// metrics pipeline and the reachability probe, surfacing the systems
// currently in breach as active alerts. Rules are persisted with their
// condition (a curated metric + comparator + threshold, a raw PromQL
// expression, or a reachability check), a "for" duration, a severity,
// and a target spec; a runtime ticker walks the enabled rules on a
// cadence and reconciles firing state. Delivery channels, routing, and
// quiet-hours are deliberately out of this package — see the roadmap.
//
// The threshold-in-Go design (rather than an Alertmanager sibling) is
// the path chosen in research/metrics-pipeline.md: it keeps rules
// user-configurable from the SPA, reuses the existing Prometheus query
// path, and mirrors the internal/schedules ticker.
package alerts

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"system-wrangler-backend/internal/targeting"
)

// Sentinel errors returned by the alerts package.
var (
	ErrNotFound = errors.New("alert rule not found")
	ErrInvalid  = errors.New("invalid alert rule")
)

const (
	maxNameLen   = 255
	maxDescLen   = 1024
	maxExprLen   = 4096
	maxForSecond = 86400 // 24h — past this a "for" duration is almost certainly a mistake.
)

// ConditionKind selects how a rule decides whether a system is in breach.
//
//   - KindMetric: a curated Metric (cross-OS PromQL the charts already use)
//     compared against Threshold by Comparator.
//   - KindPromQL: a raw PromQL expression (must yield a per-system vector
//     carrying a system_id label) compared against Threshold by Comparator.
//   - KindUnreachable: the system's reachability status is "unreachable".
//     Metric / Expr / Comparator / Threshold are ignored.
type ConditionKind string

// ConditionKind values.
const (
	KindMetric      ConditionKind = "metric"
	KindPromQL      ConditionKind = "promql"
	KindUnreachable ConditionKind = "unreachable"
)

// Comparator is the relation between an observed value and the threshold.
type Comparator string

// Comparator values.
const (
	GreaterThan      Comparator = "gt"
	GreaterThanEqual Comparator = "gte"
	LessThan         Comparator = "lt"
	LessThanEqual    Comparator = "lte"
)

// IsValid reports whether c is one of the four known comparators.
func (c Comparator) IsValid() bool {
	switch c {
	case GreaterThan, GreaterThanEqual, LessThan, LessThanEqual:
		return true
	default:
		return false
	}
}

// Breaches reports whether value trips the comparator against threshold.
func (c Comparator) Breaches(value, threshold float64) bool {
	switch c {
	case GreaterThan:
		return value > threshold
	case GreaterThanEqual:
		return value >= threshold
	case LessThan:
		return value < threshold
	case LessThanEqual:
		return value <= threshold
	default:
		return false
	}
}

// Severity is an operator-assigned label rendered alongside an alert.
// It carries no behavior in this phase — routing and quiet-hours that
// branch on severity are later roadmap items.
type Severity string

// Severity values.
const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// IsValid reports whether s is one of the three known severities.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return true
	default:
		return false
	}
}

// Rule is the persisted representation of one alert rule.
type Rule struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	ConditionKind ConditionKind  `json:"conditionKind"`
	Metric        Metric         `json:"metric,omitempty"`
	Expr          string         `json:"expr,omitempty"`
	Comparator    Comparator     `json:"comparator,omitempty"`
	Threshold     float64        `json:"threshold"`
	ForSeconds    int            `json:"forSeconds"`
	Severity      Severity       `json:"severity"`
	TargetKind    targeting.Kind `json:"targetKind"`
	TargetValue   string         `json:"targetValue"`
	Enabled       bool           `json:"enabled"`
	CreatedBy     string         `json:"createdBy"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
}

// RuleInput is the operator-supplied subset accepted on create and
// update. Server-managed fields (id, createdBy, timestamps) are filled
// by the store.
type RuleInput struct {
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	ConditionKind ConditionKind  `json:"conditionKind"`
	Metric        Metric         `json:"metric"`
	Expr          string         `json:"expr"`
	Comparator    Comparator     `json:"comparator"`
	Threshold     float64        `json:"threshold"`
	ForSeconds    int            `json:"forSeconds"`
	Severity      Severity       `json:"severity"`
	TargetKind    targeting.Kind `json:"targetKind"`
	TargetValue   string         `json:"targetValue"`
	Enabled       bool           `json:"enabled"`
}

// Validate normalizes and checks the input, returning ErrInvalid
// wrapped with a precise reason. On success the input's string fields
// are trimmed and Severity defaulted so the caller persists the
// canonical form. For KindUnreachable the metric/expr/comparator/
// threshold fields are cleared, since they carry no meaning there and
// keeping stale values would only confuse the editor on the round-trip.
func (in *RuleInput) Validate() error {
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	in.Expr = strings.TrimSpace(in.Expr)
	in.TargetValue = strings.TrimSpace(in.TargetValue)

	if in.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if len(in.Name) > maxNameLen {
		return fmt.Errorf("%w: name exceeds %d chars", ErrInvalid, maxNameLen)
	}
	if len(in.Description) > maxDescLen {
		return fmt.Errorf("%w: description exceeds %d chars", ErrInvalid, maxDescLen)
	}
	if in.Severity == "" {
		in.Severity = SeverityWarning
	}
	if !in.Severity.IsValid() {
		return fmt.Errorf("%w: severity %q is not one of info/warning/critical", ErrInvalid, in.Severity)
	}
	if in.ForSeconds < 0 {
		return fmt.Errorf("%w: forSeconds must not be negative", ErrInvalid)
	}
	if in.ForSeconds > maxForSecond {
		return fmt.Errorf("%w: forSeconds exceeds %d (24h)", ErrInvalid, maxForSecond)
	}

	switch in.ConditionKind {
	case KindMetric:
		if !in.Metric.IsValid() {
			return fmt.Errorf("%w: metric %q is not in the catalog", ErrInvalid, in.Metric)
		}
		if err := validateThreshold(in.Comparator, in.Threshold); err != nil {
			return err
		}
		in.Expr = ""
	case KindPromQL:
		if in.Expr == "" {
			return fmt.Errorf("%w: expr is required when conditionKind=promql", ErrInvalid)
		}
		if len(in.Expr) > maxExprLen {
			return fmt.Errorf("%w: expr exceeds %d chars", ErrInvalid, maxExprLen)
		}
		if err := validateThreshold(in.Comparator, in.Threshold); err != nil {
			return err
		}
		in.Metric = ""
	case KindUnreachable:
		in.Metric = ""
		in.Expr = ""
		in.Comparator = ""
		in.Threshold = 0
	default:
		return fmt.Errorf("%w: conditionKind %q is not one of metric/promql/unreachable", ErrInvalid, in.ConditionKind)
	}

	if err := targeting.ValidateValue(in.TargetKind, in.TargetValue); err != nil {
		// Re-wrap as the alerts sentinel so handlers map it to 400 with
		// errors.Is(err, ErrInvalid) without importing targeting.
		return fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	return nil
}

func validateThreshold(c Comparator, threshold float64) error {
	if !c.IsValid() {
		return fmt.Errorf("%w: comparator %q is not one of gt/gte/lt/lte", ErrInvalid, c)
	}
	if math.IsNaN(threshold) || math.IsInf(threshold, 0) {
		return fmt.Errorf("%w: threshold must be a finite number", ErrInvalid)
	}
	return nil
}

// State is the lifecycle phase of an alert instance.
//
//   - StatePending: the condition is breaching but has not yet held for
//     the rule's "for" duration.
//   - StateFiring: the condition has held long enough; the alert is live.
type State string

// State values.
const (
	StatePending State = "pending"
	StateFiring  State = "firing"
)

// Instance is the live evaluation state for one (rule, system) pair.
// It exists only while the system is in breach; clearing the breach
// deletes the row.
type Instance struct {
	RuleID        string     `json:"ruleId"`
	SystemID      string     `json:"systemId"`
	State         State      `json:"state"`
	Value         float64    `json:"value"`
	FirstBreachAt time.Time  `json:"firstBreachAt"`
	FiredAt       *time.Time `json:"firedAt,omitempty"`
	LastEvalAt    time.Time  `json:"lastEvalAt"`
}

// ActiveAlert is an Instance joined with the parent rule's descriptive
// fields, shaped for GET /api/alerts/active. SystemName is filled by the
// handler from the inventory so the SPA need not resolve it.
type ActiveAlert struct {
	Instance
	RuleName      string        `json:"ruleName"`
	Severity      Severity      `json:"severity"`
	ConditionKind ConditionKind `json:"conditionKind"`
	Metric        Metric        `json:"metric,omitempty"`
	Comparator    Comparator    `json:"comparator,omitempty"`
	Threshold     float64       `json:"threshold"`
	SystemName    string        `json:"systemName,omitempty"`
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("alerts: rand.Read: %w", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
