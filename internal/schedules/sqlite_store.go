// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SQLiteStore persists schedules + run history to SQLite. Tables are
// STRICT; migrations are pragma-probed so re-running NewSQLiteStore
// on an already-initialised db is a no-op.
type SQLiteStore struct {
	db *sql.DB

	NewID func() string
	Now   func() time.Time
}

// NewSQLiteStore creates the tables if needed and returns a Store.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schedules: schema: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS schedules (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    cron_expr           TEXT NOT NULL,
    timezone            TEXT NOT NULL,
    run_check           INTEGER NOT NULL,
    run_apply           INTEGER NOT NULL,
    reboot_after_apply  INTEGER NOT NULL,
    target_kind         TEXT NOT NULL,
    target_value        TEXT NOT NULL,
    enabled             INTEGER NOT NULL,
    next_run_at         INTEGER,
    last_run_at         INTEGER,
    last_status         TEXT,
    created_by          TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS schedules_due ON schedules(enabled, next_run_at);

CREATE TABLE IF NOT EXISTS schedule_runs (
    id                  TEXT PRIMARY KEY,
    schedule_id         TEXT NOT NULL,
    started_at          INTEGER NOT NULL,
    finished_at         INTEGER,
    status              TEXT NOT NULL,
    targets_attempted   INTEGER NOT NULL DEFAULT 0,
    targets_succeeded   INTEGER NOT NULL DEFAULT 0,
    targets_failed      INTEGER NOT NULL DEFAULT 0,
    message             TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS schedule_runs_by_schedule ON schedule_runs(schedule_id, started_at);
`

// Create inserts a new schedule. createdBy must be a non-empty user id.
func (s *SQLiteStore) Create(in ScheduleInput, createdBy string) (Schedule, error) {
	if err := in.Validate(); err != nil {
		return Schedule{}, err
	}
	if createdBy == "" {
		return Schedule{}, fmt.Errorf("%w: createdBy is required", ErrInvalid)
	}
	now := s.Now().UTC()
	next, err := computeNext(in.CronExpr, in.Timezone, now)
	if err != nil {
		return Schedule{}, err
	}
	sch := Schedule{
		ID:               s.NewID(),
		Name:             in.Name,
		CronExpr:         in.CronExpr,
		Timezone:         in.Timezone,
		RunCheck:         in.RunCheck,
		RunApply:         in.RunApply,
		RebootAfterApply: in.RebootAfterApply,
		TargetKind:       in.TargetKind,
		TargetValue:      in.TargetValue,
		Enabled:          in.Enabled,
		CreatedBy:        createdBy,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if in.Enabled {
		sch.NextRunAt = &next
	}
	if _, err := s.db.Exec(
		`INSERT INTO schedules
		   (id, name, cron_expr, timezone, run_check, run_apply, reboot_after_apply,
		    target_kind, target_value, enabled, next_run_at, last_run_at, last_status,
		    created_by, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?)`,
		sch.ID, sch.Name, sch.CronExpr, sch.Timezone,
		boolToInt(sch.RunCheck), boolToInt(sch.RunApply), boolToInt(sch.RebootAfterApply),
		string(sch.TargetKind), sch.TargetValue, boolToInt(sch.Enabled),
		nullableNanos(sch.NextRunAt),
		sch.CreatedBy, sch.CreatedAt.UnixNano(), sch.UpdatedAt.UnixNano(),
	); err != nil {
		return Schedule{}, fmt.Errorf("schedules: insert: %w", err)
	}
	return sch, nil
}

// Get returns the schedule with the given id or ErrNotFound.
func (s *SQLiteStore) Get(id string) (Schedule, error) {
	row := s.db.QueryRow(`SELECT `+columns+` FROM schedules WHERE id = ?`, id)
	sch, err := scanSchedule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Schedule{}, ErrNotFound
	}
	return sch, err
}

// List returns every schedule ordered by created_at, id.
func (s *SQLiteStore) List() ([]Schedule, error) {
	rows, err := s.db.Query(`SELECT ` + columns + ` FROM schedules ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("schedules: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Schedule{}
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, fmt.Errorf("schedules: scan: %w", err)
		}
		out = append(out, sch)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("schedules: list rows: %w", err)
	}
	return out, nil
}

// Update replaces an existing schedule and recomputes NextRunAt.
func (s *SQLiteStore) Update(id string, in ScheduleInput) (Schedule, error) {
	if err := in.Validate(); err != nil {
		return Schedule{}, err
	}
	now := s.Now().UTC()
	var nextPtr *time.Time
	if in.Enabled {
		next, err := computeNext(in.CronExpr, in.Timezone, now)
		if err != nil {
			return Schedule{}, err
		}
		nextPtr = &next
	}
	res, err := s.db.Exec(
		`UPDATE schedules SET
		   name = ?, cron_expr = ?, timezone = ?,
		   run_check = ?, run_apply = ?, reboot_after_apply = ?,
		   target_kind = ?, target_value = ?, enabled = ?,
		   next_run_at = ?, updated_at = ?
		 WHERE id = ?`,
		in.Name, in.CronExpr, in.Timezone,
		boolToInt(in.RunCheck), boolToInt(in.RunApply), boolToInt(in.RebootAfterApply),
		string(in.TargetKind), in.TargetValue, boolToInt(in.Enabled),
		nullableNanos(nextPtr), now.UnixNano(),
		id,
	)
	if err != nil {
		return Schedule{}, fmt.Errorf("schedules: update: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Schedule{}, ErrNotFound
	}
	return s.Get(id)
}

// Delete removes a schedule and its run history.
func (s *SQLiteStore) Delete(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("schedules: delete begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM schedule_runs WHERE schedule_id = ?`, id); err != nil {
		return fmt.Errorf("schedules: delete runs: %w", err)
	}
	res, err := tx.Exec(`DELETE FROM schedules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("schedules: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// SetEnabled flips the schedule's enabled flag, recomputing or
// clearing NextRunAt as appropriate.
func (s *SQLiteStore) SetEnabled(id string, enabled bool) (Schedule, error) {
	current, err := s.Get(id)
	if err != nil {
		return Schedule{}, err
	}
	now := s.Now().UTC()
	var nextPtr *time.Time
	if enabled {
		next, err := computeNext(current.CronExpr, current.Timezone, now)
		if err != nil {
			return Schedule{}, err
		}
		nextPtr = &next
	}
	if _, err := s.db.Exec(
		`UPDATE schedules SET enabled = ?, next_run_at = ?, updated_at = ? WHERE id = ?`,
		boolToInt(enabled), nullableNanos(nextPtr), now.UnixNano(), id,
	); err != nil {
		return Schedule{}, fmt.Errorf("schedules: set enabled: %w", err)
	}
	return s.Get(id)
}

// RecordRunStart inserts a new schedule_runs row in `running` status.
func (s *SQLiteStore) RecordRunStart(scheduleID string) (ScheduleRun, error) {
	now := s.Now().UTC()
	run := ScheduleRun{
		ID:         s.NewID(),
		ScheduleID: scheduleID,
		StartedAt:  now,
		Status:     StatusRunning,
	}
	if _, err := s.db.Exec(
		`INSERT INTO schedule_runs (id, schedule_id, started_at, status) VALUES (?, ?, ?, ?)`,
		run.ID, run.ScheduleID, run.StartedAt.UnixNano(), string(run.Status),
	); err != nil {
		return ScheduleRun{}, fmt.Errorf("schedules: insert run: %w", err)
	}
	return run, nil
}

// RecordRunFinish patches a schedule_runs row with the final status
// and advances the parent schedule's last_run_at / last_status /
// next_run_at in the same transaction.
func (s *SQLiteStore) RecordRunFinish(runID string, status RunStatus, attempted, succeeded, failed int, message string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("schedules: finish begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := s.Now().UTC()
	// Update the run row and capture its schedule_id so we can patch
	// the parent's last_* fields in the same transaction.
	row := tx.QueryRow(`SELECT schedule_id FROM schedule_runs WHERE id = ?`, runID)
	var scheduleID string
	if err := row.Scan(&scheduleID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("schedules: lookup run: %w", err)
	}
	if _, err := tx.Exec(
		`UPDATE schedule_runs SET status = ?, finished_at = ?, targets_attempted = ?, targets_succeeded = ?, targets_failed = ?, message = ? WHERE id = ?`,
		string(status), now.UnixNano(), attempted, succeeded, failed, message, runID,
	); err != nil {
		return fmt.Errorf("schedules: update run: %w", err)
	}
	// Advance NextRunAt off the current clock for this schedule —
	// the parent's last_run_at/last_status reflect this finishing
	// run, and NextRunAt slides forward to the next fire that's
	// strictly after `now`.
	var (
		cronExpr string
		timezone string
		enabled  int
	)
	if err := tx.QueryRow(
		`SELECT cron_expr, timezone, enabled FROM schedules WHERE id = ?`, scheduleID,
	).Scan(&cronExpr, &timezone, &enabled); err != nil {
		return fmt.Errorf("schedules: lookup parent: %w", err)
	}
	var nextPtr *time.Time
	if enabled == 1 {
		next, err := computeNext(cronExpr, timezone, now)
		if err != nil {
			return fmt.Errorf("schedules: compute next: %w", err)
		}
		nextPtr = &next
	}
	if _, err := tx.Exec(
		`UPDATE schedules SET last_run_at = ?, last_status = ?, next_run_at = ? WHERE id = ?`,
		now.UnixNano(), string(status), nullableNanos(nextPtr), scheduleID,
	); err != nil {
		return fmt.Errorf("schedules: update parent: %w", err)
	}
	return tx.Commit()
}

// ListRuns returns the schedule's run history, most recent first.
func (s *SQLiteStore) ListRuns(scheduleID string, limit int) ([]ScheduleRun, error) {
	if limit <= 0 {
		limit = 1 << 30
	}
	rows, err := s.db.Query(
		`SELECT id, schedule_id, started_at, finished_at, status,
		        targets_attempted, targets_succeeded, targets_failed, message
		 FROM schedule_runs WHERE schedule_id = ?
		 ORDER BY started_at DESC, id DESC
		 LIMIT ?`,
		scheduleID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("schedules: list runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []ScheduleRun{}
	for rows.Next() {
		var (
			r          ScheduleRun
			startedNs  int64
			finishedNs sql.NullInt64
			msg        sql.NullString
			status     string
		)
		if err := rows.Scan(
			&r.ID, &r.ScheduleID, &startedNs, &finishedNs, &status,
			&r.TargetsAttempted, &r.TargetsSucceeded, &r.TargetsFailed, &msg,
		); err != nil {
			return nil, fmt.Errorf("schedules: scan run: %w", err)
		}
		r.StartedAt = time.Unix(0, startedNs).UTC()
		if finishedNs.Valid {
			t := time.Unix(0, finishedNs.Int64).UTC()
			r.FinishedAt = &t
		}
		r.Status = RunStatus(status)
		if msg.Valid {
			r.Message = msg.String
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("schedules: list runs rows: %w", err)
	}
	return out, nil
}

// Due returns enabled schedules whose NextRunAt is at or before `now`.
func (s *SQLiteStore) Due(now time.Time) ([]Schedule, error) {
	rows, err := s.db.Query(
		`SELECT `+columns+` FROM schedules WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ? ORDER BY next_run_at, id`,
		now.UTC().UnixNano(),
	)
	if err != nil {
		return nil, fmt.Errorf("schedules: due: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Schedule{}
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, fmt.Errorf("schedules: scan due: %w", err)
		}
		out = append(out, sch)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("schedules: due rows: %w", err)
	}
	return out, nil
}

// ReconcileMissed advances enabled schedules whose NextRunAt fell more
// than `grace` before `now` to their next future occurrence, without
// running them, and returns the rescheduled schedules carrying the
// missed NextRunAt. See the Store interface for why this exists. The
// scan happens before any write so the cursor is closed before the
// per-row updates run on the same connection.
func (s *SQLiteStore) ReconcileMissed(now time.Time, grace time.Duration) ([]Schedule, error) {
	cutoff := now.UTC().Add(-grace)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("schedules: reconcile begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.Query(
		`SELECT `+columns+` FROM schedules WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at < ? ORDER BY next_run_at, id`,
		cutoff.UnixNano(),
	)
	if err != nil {
		return nil, fmt.Errorf("schedules: reconcile select: %w", err)
	}
	missed := []Schedule{}
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("schedules: scan missed: %w", err)
		}
		missed = append(missed, sch)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("schedules: reconcile rows: %w", err)
	}
	_ = rows.Close()

	for _, sch := range missed {
		next, err := computeNext(sch.CronExpr, sch.Timezone, now.UTC())
		if err != nil {
			return nil, fmt.Errorf("schedules: reconcile compute next: %w", err)
		}
		if _, err := tx.Exec(
			`UPDATE schedules SET next_run_at = ? WHERE id = ?`,
			next.UnixNano(), sch.ID,
		); err != nil {
			return nil, fmt.Errorf("schedules: reconcile update: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("schedules: reconcile commit: %w", err)
	}
	return missed, nil
}

const columns = `id, name, cron_expr, timezone, run_check, run_apply, reboot_after_apply,
                  target_kind, target_value, enabled, next_run_at, last_run_at, last_status,
                  created_by, created_at, updated_at`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSchedule(r rowScanner) (Schedule, error) {
	var (
		sch                        Schedule
		runCheck, runApply, reboot int
		enabled                    int
		nextNs, lastNs             sql.NullInt64
		lastStatus                 sql.NullString
		createdNs, updatedNs       int64
		targetKind                 string
	)
	if err := r.Scan(
		&sch.ID, &sch.Name, &sch.CronExpr, &sch.Timezone,
		&runCheck, &runApply, &reboot,
		&targetKind, &sch.TargetValue, &enabled,
		&nextNs, &lastNs, &lastStatus,
		&sch.CreatedBy, &createdNs, &updatedNs,
	); err != nil {
		return Schedule{}, err
	}
	sch.RunCheck = runCheck == 1
	sch.RunApply = runApply == 1
	sch.RebootAfterApply = reboot == 1
	sch.Enabled = enabled == 1
	sch.TargetKind = TargetKind(targetKind)
	if nextNs.Valid {
		t := time.Unix(0, nextNs.Int64).UTC()
		sch.NextRunAt = &t
	}
	if lastNs.Valid {
		t := time.Unix(0, lastNs.Int64).UTC()
		sch.LastRunAt = &t
	}
	if lastStatus.Valid {
		st := RunStatus(lastStatus.String)
		sch.LastStatus = &st
	}
	sch.CreatedAt = time.Unix(0, createdNs).UTC()
	sch.UpdatedAt = time.Unix(0, updatedNs).UTC()
	return sch, nil
}

func computeNext(expr, tz string, after time.Time) (time.Time, error) {
	c, err := ParseCron(expr)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: timezone %q: %s", ErrInvalid, tz, err.Error())
	}
	next, err := c.Next(after.In(loc))
	if err != nil {
		return time.Time{}, err
	}
	return next.UTC(), nil
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
