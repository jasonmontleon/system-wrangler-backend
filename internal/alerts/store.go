// SPDX-License-Identifier: Apache-2.0

package alerts

// Store is the persistence contract for alert rules and the live
// instance state the evaluator reconciles. Rule methods are ordinary
// CRUD; the instance methods are deliberately primitive (put one,
// delete one) so the firing-state transition logic lives in the
// evaluator and stays unit-testable against a fake store.
type Store interface {
	Create(in RuleInput, createdBy string) (Rule, error)
	Get(id string) (Rule, error)
	List() ([]Rule, error)
	// ListEnabled returns only enabled rules — the set the evaluator walks.
	ListEnabled() ([]Rule, error)
	Update(id string, in RuleInput) (Rule, error)
	Delete(id string) error

	// InstancesForRule returns the live instances (pending + firing)
	// for one rule, which the evaluator diffs against the current breach
	// set each tick.
	InstancesForRule(ruleID string) ([]Instance, error)

	// PutInstance upserts a single instance row (PK rule_id+system_id).
	PutInstance(inst Instance) error

	// DeleteInstance removes one instance — used when a system clears
	// its breach.
	DeleteInstance(ruleID, systemID string) error

	// ListActive returns every live instance joined with its parent
	// rule's descriptive fields, for GET /api/alerts/active. Rows for
	// disabled or deleted rules are excluded.
	ListActive() ([]ActiveAlert, error)
}
