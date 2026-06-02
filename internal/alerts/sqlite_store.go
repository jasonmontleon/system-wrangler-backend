// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"system-wrangler-backend/internal/targeting"
)

// SQLiteStore persists alert rules + live instance state to SQLite.
// Tables are STRICT; the schema is pragma-probed (CREATE IF NOT EXISTS)
// so re-running NewSQLiteStore on an initialised db is a no-op.
type SQLiteStore struct {
	db *sql.DB

	NewID func() string
	Now   func() time.Time
}

// NewSQLiteStore creates the tables if needed and returns a Store.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("alerts: schema: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS alert_rules (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    condition_kind  TEXT NOT NULL,
    metric          TEXT NOT NULL DEFAULT '',
    expr            TEXT NOT NULL DEFAULT '',
    comparator      TEXT NOT NULL DEFAULT '',
    threshold       REAL NOT NULL DEFAULT 0,
    for_seconds     INTEGER NOT NULL DEFAULT 0,
    severity        TEXT NOT NULL,
    target_kind     TEXT NOT NULL,
    target_value    TEXT NOT NULL,
    enabled         INTEGER NOT NULL,
    created_by      TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS alert_rules_enabled ON alert_rules(enabled);

CREATE TABLE IF NOT EXISTS alert_instances (
    rule_id         TEXT NOT NULL,
    system_id       TEXT NOT NULL,
    state           TEXT NOT NULL,
    value           REAL NOT NULL DEFAULT 0,
    first_breach_at INTEGER NOT NULL,
    fired_at        INTEGER,
    last_eval_at    INTEGER NOT NULL,
    PRIMARY KEY (rule_id, system_id)
) STRICT;

CREATE INDEX IF NOT EXISTS alert_instances_by_rule ON alert_instances(rule_id);
`

const ruleColumns = `id, name, description, condition_kind, metric, expr, comparator,
                     threshold, for_seconds, severity, target_kind, target_value,
                     enabled, created_by, created_at, updated_at`

// Create inserts a new rule. createdBy must be a non-empty user id.
func (s *SQLiteStore) Create(in RuleInput, createdBy string) (Rule, error) {
	if err := in.Validate(); err != nil {
		return Rule{}, err
	}
	if createdBy == "" {
		return Rule{}, fmt.Errorf("%w: createdBy is required", ErrInvalid)
	}
	now := s.Now().UTC()
	r := ruleFromInput(in)
	r.ID = s.NewID()
	r.CreatedBy = createdBy
	r.CreatedAt = now
	r.UpdatedAt = now
	if _, err := s.db.Exec(
		`INSERT INTO alert_rules
		   (id, name, description, condition_kind, metric, expr, comparator,
		    threshold, for_seconds, severity, target_kind, target_value,
		    enabled, created_by, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, r.Description, string(r.ConditionKind), string(r.Metric), r.Expr,
		string(r.Comparator), r.Threshold, r.ForSeconds, string(r.Severity),
		string(r.TargetKind), r.TargetValue, boolToInt(r.Enabled),
		r.CreatedBy, r.CreatedAt.UnixNano(), r.UpdatedAt.UnixNano(),
	); err != nil {
		return Rule{}, fmt.Errorf("alerts: insert: %w", err)
	}
	return r, nil
}

// Get returns the rule with the given id or ErrNotFound.
func (s *SQLiteStore) Get(id string) (Rule, error) {
	row := s.db.QueryRow(`SELECT `+ruleColumns+` FROM alert_rules WHERE id = ?`, id)
	r, err := scanRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	return r, err
}

// List returns every rule ordered by created_at, id.
func (s *SQLiteStore) List() ([]Rule, error) {
	return s.queryRules(`SELECT ` + ruleColumns + ` FROM alert_rules ORDER BY created_at, id`)
}

// ListEnabled returns enabled rules ordered by created_at, id.
func (s *SQLiteStore) ListEnabled() ([]Rule, error) {
	return s.queryRules(`SELECT ` + ruleColumns + ` FROM alert_rules WHERE enabled = 1 ORDER BY created_at, id`)
}

func (s *SQLiteStore) queryRules(query string, args ...any) ([]Rule, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("alerts: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Rule{}
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, fmt.Errorf("alerts: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("alerts: list rows: %w", err)
	}
	return out, nil
}

// Update replaces an existing rule. A rule that becomes disabled has its
// active instances cleared in the same transaction.
func (s *SQLiteStore) Update(id string, in RuleInput) (Rule, error) {
	if err := in.Validate(); err != nil {
		return Rule{}, err
	}
	now := s.Now().UTC()
	r := ruleFromInput(in)
	tx, err := s.db.Begin()
	if err != nil {
		return Rule{}, fmt.Errorf("alerts: update begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(
		`UPDATE alert_rules SET
		   name = ?, description = ?, condition_kind = ?, metric = ?, expr = ?,
		   comparator = ?, threshold = ?, for_seconds = ?, severity = ?,
		   target_kind = ?, target_value = ?, enabled = ?, updated_at = ?
		 WHERE id = ?`,
		r.Name, r.Description, string(r.ConditionKind), string(r.Metric), r.Expr,
		string(r.Comparator), r.Threshold, r.ForSeconds, string(r.Severity),
		string(r.TargetKind), r.TargetValue, boolToInt(r.Enabled), now.UnixNano(),
		id,
	)
	if err != nil {
		return Rule{}, fmt.Errorf("alerts: update: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Rule{}, ErrNotFound
	}
	if !r.Enabled {
		if _, err := tx.Exec(`DELETE FROM alert_instances WHERE rule_id = ?`, id); err != nil {
			return Rule{}, fmt.Errorf("alerts: clear instances: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Rule{}, fmt.Errorf("alerts: update commit: %w", err)
	}
	return s.Get(id)
}

// Delete removes a rule and its instances.
func (s *SQLiteStore) Delete(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("alerts: delete begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM alert_instances WHERE rule_id = ?`, id); err != nil {
		return fmt.Errorf("alerts: delete instances: %w", err)
	}
	res, err := tx.Exec(`DELETE FROM alert_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("alerts: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// InstancesForRule returns the live instances for one rule.
func (s *SQLiteStore) InstancesForRule(ruleID string) ([]Instance, error) {
	rows, err := s.db.Query(
		`SELECT rule_id, system_id, state, value, first_breach_at, fired_at, last_eval_at
		 FROM alert_instances WHERE rule_id = ? ORDER BY system_id`,
		ruleID,
	)
	if err != nil {
		return nil, fmt.Errorf("alerts: instances: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Instance{}
	for rows.Next() {
		inst, err := scanInstance(rows)
		if err != nil {
			return nil, fmt.Errorf("alerts: scan instance: %w", err)
		}
		out = append(out, inst)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("alerts: instances rows: %w", err)
	}
	return out, nil
}

// PutInstance upserts a single instance row.
func (s *SQLiteStore) PutInstance(inst Instance) error {
	_, err := s.db.Exec(
		`INSERT INTO alert_instances
		   (rule_id, system_id, state, value, first_breach_at, fired_at, last_eval_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(rule_id, system_id) DO UPDATE SET
		   state = excluded.state, value = excluded.value,
		   first_breach_at = excluded.first_breach_at,
		   fired_at = excluded.fired_at, last_eval_at = excluded.last_eval_at`,
		inst.RuleID, inst.SystemID, string(inst.State), inst.Value,
		inst.FirstBreachAt.UnixNano(), nullableNanos(inst.FiredAt), inst.LastEvalAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("alerts: put instance: %w", err)
	}
	return nil
}

// DeleteInstance removes one instance. Deleting an absent row is a no-op.
func (s *SQLiteStore) DeleteInstance(ruleID, systemID string) error {
	if _, err := s.db.Exec(
		`DELETE FROM alert_instances WHERE rule_id = ? AND system_id = ?`, ruleID, systemID,
	); err != nil {
		return fmt.Errorf("alerts: delete instance: %w", err)
	}
	return nil
}

// ListActive joins live instances with their parent rule's descriptive
// fields, excluding disabled/deleted rules. Firing alerts sort ahead of
// pending, then by most-recent breach.
func (s *SQLiteStore) ListActive() ([]ActiveAlert, error) {
	rows, err := s.db.Query(
		`SELECT i.rule_id, i.system_id, i.state, i.value, i.first_breach_at, i.fired_at, i.last_eval_at,
		        r.name, r.severity, r.condition_kind, r.metric, r.comparator, r.threshold
		 FROM alert_instances i
		 JOIN alert_rules r ON r.id = i.rule_id
		 WHERE r.enabled = 1
		 ORDER BY (i.state = 'firing') DESC, i.first_breach_at, i.rule_id, i.system_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("alerts: active: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []ActiveAlert{}
	for rows.Next() {
		var (
			a             ActiveAlert
			state         string
			firstNs       int64
			firedNs       sql.NullInt64
			lastNs        int64
			severity      string
			conditionKind string
			metric        string
			comparator    string
		)
		if err := rows.Scan(
			&a.RuleID, &a.SystemID, &state, &a.Value, &firstNs, &firedNs, &lastNs,
			&a.RuleName, &severity, &conditionKind, &metric, &comparator, &a.Threshold,
		); err != nil {
			return nil, fmt.Errorf("alerts: scan active: %w", err)
		}
		a.State = State(state)
		a.FirstBreachAt = time.Unix(0, firstNs).UTC()
		if firedNs.Valid {
			t := time.Unix(0, firedNs.Int64).UTC()
			a.FiredAt = &t
		}
		a.LastEvalAt = time.Unix(0, lastNs).UTC()
		a.Severity = Severity(severity)
		a.ConditionKind = ConditionKind(conditionKind)
		a.Metric = Metric(metric)
		a.Comparator = Comparator(comparator)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("alerts: active rows: %w", err)
	}
	return out, nil
}

func ruleFromInput(in RuleInput) Rule {
	return Rule{
		Name:          in.Name,
		Description:   in.Description,
		ConditionKind: in.ConditionKind,
		Metric:        in.Metric,
		Expr:          in.Expr,
		Comparator:    in.Comparator,
		Threshold:     in.Threshold,
		ForSeconds:    in.ForSeconds,
		Severity:      in.Severity,
		TargetKind:    in.TargetKind,
		TargetValue:   in.TargetValue,
		Enabled:       in.Enabled,
	}
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRule(r rowScanner) (Rule, error) {
	var (
		rule                 Rule
		conditionKind        string
		metric               string
		comparator           string
		severity             string
		targetKind           string
		enabled              int
		createdNs, updatedNs int64
	)
	if err := r.Scan(
		&rule.ID, &rule.Name, &rule.Description, &conditionKind, &metric, &rule.Expr,
		&comparator, &rule.Threshold, &rule.ForSeconds, &severity, &targetKind,
		&rule.TargetValue, &enabled, &rule.CreatedBy, &createdNs, &updatedNs,
	); err != nil {
		return Rule{}, err
	}
	rule.ConditionKind = ConditionKind(conditionKind)
	rule.Metric = Metric(metric)
	rule.Comparator = Comparator(comparator)
	rule.Severity = Severity(severity)
	rule.TargetKind = targeting.Kind(targetKind)
	rule.Enabled = enabled == 1
	rule.CreatedAt = time.Unix(0, createdNs).UTC()
	rule.UpdatedAt = time.Unix(0, updatedNs).UTC()
	return rule, nil
}

func scanInstance(r rowScanner) (Instance, error) {
	var (
		inst    Instance
		state   string
		firstNs int64
		firedNs sql.NullInt64
		lastNs  int64
	)
	if err := r.Scan(
		&inst.RuleID, &inst.SystemID, &state, &inst.Value, &firstNs, &firedNs, &lastNs,
	); err != nil {
		return Instance{}, err
	}
	inst.State = State(state)
	inst.FirstBreachAt = time.Unix(0, firstNs).UTC()
	if firedNs.Valid {
		t := time.Unix(0, firedNs.Int64).UTC()
		inst.FiredAt = &t
	}
	inst.LastEvalAt = time.Unix(0, lastNs).UTC()
	return inst, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableNanos(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixNano()
}
