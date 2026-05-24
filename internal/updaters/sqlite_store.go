// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Store is the persistence boundary for custom updater definitions,
// per-system availability rows, and run history. SQLiteStore is the
// production implementation; downstream packages compose against
// this interface.
type Store interface {
	// ListCustom returns every non-deleted custom updater definition.
	// Soft-deleted rows are excluded — see GetCustom for the
	// audit/history retrieval path.
	ListCustom() ([]Definition, error)
	// GetCustom returns one custom definition by id. Returns
	// soft-deleted rows so audit and run-history lookups can render
	// the historical name.
	GetCustom(id string) (Definition, error)
	// CreateCustom inserts a new custom definition. Returns
	// ErrDuplicate if the id is already taken (including by a
	// tombstoned row).
	CreateCustom(d Definition) (Definition, error)
	// UpdateCustom rewrites the mutable fields of an existing
	// non-deleted custom definition. Returns ErrNotFound when the id
	// is unknown or already soft-deleted.
	UpdateCustom(d Definition) (Definition, error)
	// DeleteCustom soft-deletes the row by stamping deleted_at.
	// Subsequent ListCustom calls skip it; GetCustom still returns
	// it.
	DeleteCustom(id string, at time.Time) error

	// UpsertAvailability records or refreshes "system X has updater
	// Y detected" with last_seen_at = now. New rows default to
	// enabled=true; existing rows keep their enabled flag.
	UpsertAvailability(systemID, updaterID string, at time.Time) error
	// RemoveAvailability deletes a single (system, updater) row.
	RemoveAvailability(systemID, updaterID string) error
	// AvailabilityFor returns every updater detected on systemID.
	AvailabilityFor(systemID string) ([]Availability, error)
	// SetEnabled toggles the operator's per-system enabled flag on
	// a detected updater. Returns ErrNotFound if no row exists for
	// (systemID, updaterID) — enablement only makes sense for
	// updaters the inspection has already confirmed installed.
	SetEnabled(systemID, updaterID string, enabled bool) error
	// SetPendingPackages replaces the per-(system, updater)
	// pending-package list. Called from the runner after each check
	// run with the parsed marker output. Missing rows are silently
	// ignored — only detected updaters carry a list.
	SetPendingPackages(systemID, updaterID string, packages []PendingPackage) error

	// InsertRun stores a starting run row. The caller assigns the
	// id (so the matching audit start-row can share it).
	InsertRun(r Run) error
	// TrimRunsForSystem deletes rows for systemID older than the
	// keep-th most recent started_at. A non-positive `keep` is
	// treated as a no-op so the trim is safe to call with an
	// unparseable setting. Keep this inline rather than behind a
	// background goroutine so the table stays bounded without a
	// scheduler.
	TrimRunsForSystem(systemID string, keep int) error
	// FinishRun stamps finished_at, exit_code, affected_count and
	// log_tail on an existing run. The store truncates log_tail to
	// MaxLogTailBytes on write.
	FinishRun(id string, finishedAt time.Time, exitCode, affectedCount int, logTail string) error
	// SystemStatsAll returns one entry per system that has any
	// updater_runs row, keyed by system_id. Used by the systems
	// handler to enrich GET /api/systems with "last checked" and
	// "updates available." Systems with no runs are simply absent
	// from the map.
	SystemStatsAll() (map[string]SystemStats, error)
	// ListRuns returns the most recent runs for systemID, newest
	// first, up to limit rows. Returns soft-deleted updater rows'
	// runs too — the UI joins to GetCustom for the display name.
	ListRuns(systemID string, limit int) ([]Run, error)

	// AcquireLock takes the per-system advisory lock. Returns the
	// run id that already holds it via ErrConflict if contended.
	// runID is the new owner; ExpireLocksOlderThan reaps stuck
	// rows.
	AcquireLock(systemID, runID string, at time.Time) error
	// ReleaseLock drops the lock identified by (systemID, runID).
	// Idempotent — releasing a missing lock is not an error.
	ReleaseLock(systemID, runID string) error
	// ConflictingRun returns the run id that currently holds the
	// lock on systemID, or "" if free.
	ConflictingRun(systemID string) (string, error)
}

// SQLiteStore persists updater state. New ids are minted with the
// callers' UUID helper; Now is injected for deterministic tests.
type SQLiteStore struct {
	db *sql.DB

	NewID func() string
	Now   func() time.Time
}

// NewSQLiteStore migrates the schema and returns a ready store.
// Idempotent across boots.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if err := renameUpdaterRunLocksTable(db); err != nil {
		return nil, fmt.Errorf("updaters: migrate lock table: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("updaters: schema: %w", err)
	}
	if err := addEnabledColumn(db); err != nil {
		return nil, fmt.Errorf("updaters: migrate enabled: %w", err)
	}
	if err := addAffectedCountColumn(db); err != nil {
		return nil, fmt.Errorf("updaters: migrate affected_count: %w", err)
	}
	if err := addPendingPackagesColumn(db); err != nil {
		return nil, fmt.Errorf("updaters: migrate pending_packages: %w", err)
	}
	if err := addCheckOnlyColumn(db); err != nil {
		return nil, fmt.Errorf("updaters: migrate check_only: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

// renameUpdaterRunLocksTable moves the legacy `updater_run_locks`
// table to its current name `system_action_locks`. The lock substrate
// is shared with the exporter runner, so the original name (which
// pre-dated exporter bootstrap) was misleading. Runs before the
// schema CREATE so a fresh upgrade path doesn't briefly hold two
// parallel tables. Idempotent: a fresh DB or an already-renamed DB
// is a no-op. Also drops the old `updater_locks_cleanup_host`
// trigger so the schema-defined `system_action_locks_cleanup_host`
// is the only on-host-delete cleanup running.
func renameUpdaterRunLocksTable(db *sql.DB) error {
	var found int
	switch err := db.QueryRow(
		`SELECT 1 FROM sqlite_master WHERE type='table' AND name='updater_run_locks'`,
	).Scan(&found); {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return err
	}
	if _, err := db.Exec(`ALTER TABLE updater_run_locks RENAME TO system_action_locks`); err != nil {
		return err
	}
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS updater_locks_cleanup_host`); err != nil {
		return err
	}
	return nil
}

// addCheckOnlyColumn brings databases predating the check_only flag
// up to schema. Pragma-probe pattern; defaults to 0 (i.e. apply
// permitted) so existing custom updaters retain their behaviour
// without an operator intervention.
func addCheckOnlyColumn(db *sql.DB) error {
	row := db.QueryRow(`SELECT 1 FROM pragma_table_info('updater_definitions') WHERE name = 'check_only'`)
	var found int
	switch err := row.Scan(&found); {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		_, err := db.Exec(`ALTER TABLE updater_definitions ADD COLUMN check_only INTEGER NOT NULL DEFAULT 0`)
		return err
	default:
		return err
	}
}

// addPendingPackagesColumn brings databases predating per-package
// state up to schema. The column holds a JSON-encoded []string of
// the packages the latest check run reported pending; default '[]'
// keeps the column non-null and unmarshals cleanly for stores that
// have never been checked.
func addPendingPackagesColumn(db *sql.DB) error {
	row := db.QueryRow(`SELECT 1 FROM pragma_table_info('system_updaters') WHERE name = 'pending_packages'`)
	var found int
	switch err := row.Scan(&found); {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		_, err := db.Exec(`ALTER TABLE system_updaters ADD COLUMN pending_packages TEXT NOT NULL DEFAULT '[]'`)
		return err
	default:
		return err
	}
}

// addAffectedCountColumn brings databases predating affected_count
// up to schema. Same pragma-probe pattern as the enabled column
// migration; defaults to 0 for existing rows so summing across
// "Updates Available" reports remains well-defined.
func addAffectedCountColumn(db *sql.DB) error {
	row := db.QueryRow(`SELECT 1 FROM pragma_table_info('updater_runs') WHERE name = 'affected_count'`)
	var found int
	switch err := row.Scan(&found); {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		_, err := db.Exec(`ALTER TABLE updater_runs ADD COLUMN affected_count INTEGER NOT NULL DEFAULT 0`)
		return err
	default:
		return err
	}
}

// addEnabledColumn brings databases predating the `enabled` flag up
// to schema. SQLite has no `ADD COLUMN IF NOT EXISTS`, so we probe
// pragma_table_info and ALTER only when missing — the same shape
// systems and auth use elsewhere in the tree.
func addEnabledColumn(db *sql.DB) error {
	row := db.QueryRow(`SELECT 1 FROM pragma_table_info('system_updaters') WHERE name = 'enabled'`)
	var found int
	switch err := row.Scan(&found); {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		_, err := db.Exec(`ALTER TABLE system_updaters ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1`)
		return err
	default:
		return err
	}
}

// schema covers all four updater tables. The cascade trigger on
// hosts wipes system_updaters / updater_runs / system_action_locks
// rows when a host is deleted; updater_definitions are soft-deleted
// so audit/run-history rows still resolve the name.
//
// `system_action_locks` is shared with the exporter runner — both
// substrates serialise per-host ansible runs through the same row.
const schema = `
CREATE TABLE IF NOT EXISTS updater_definitions (
    id              TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    detect_binary   TEXT NOT NULL,
    check_playbook  TEXT NOT NULL,
    apply_playbook  TEXT NOT NULL,
    check_only      INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    deleted_at      INTEGER
) STRICT;

CREATE TABLE IF NOT EXISTS system_updaters (
    system_id        TEXT NOT NULL,
    updater_id       TEXT NOT NULL,
    last_seen_at     INTEGER,
    enabled          INTEGER NOT NULL DEFAULT 1,
    pending_packages TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (system_id, updater_id)
) STRICT;

CREATE TABLE IF NOT EXISTS updater_runs (
    id              TEXT PRIMARY KEY,
    system_id       TEXT NOT NULL,
    updater_id      TEXT NOT NULL DEFAULT '',
    kind            TEXT NOT NULL CHECK (kind IN ('inspect', 'check', 'apply')),
    started_at      INTEGER NOT NULL,
    finished_at     INTEGER,
    exit_code       INTEGER,
    affected_count  INTEGER NOT NULL DEFAULT 0,
    actor_id        TEXT NOT NULL DEFAULT '',
    playbook_sha    TEXT NOT NULL DEFAULT '',
    log_tail        TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX IF NOT EXISTS updater_runs_system  ON updater_runs(system_id, started_at DESC);
CREATE INDEX IF NOT EXISTS updater_runs_updater ON updater_runs(updater_id, started_at DESC);

CREATE TABLE IF NOT EXISTS system_action_locks (
    system_id     TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL,
    acquired_at   INTEGER NOT NULL
) STRICT;

CREATE TRIGGER IF NOT EXISTS updater_runs_cleanup_host
    AFTER DELETE ON hosts
    FOR EACH ROW
    BEGIN
        DELETE FROM updater_runs WHERE system_id = OLD.id;
    END;
CREATE TRIGGER IF NOT EXISTS updater_avail_cleanup_host
    AFTER DELETE ON hosts
    FOR EACH ROW
    BEGIN
        DELETE FROM system_updaters WHERE system_id = OLD.id;
    END;
CREATE TRIGGER IF NOT EXISTS system_action_locks_cleanup_host
    AFTER DELETE ON hosts
    FOR EACH ROW
    BEGIN
        DELETE FROM system_action_locks WHERE system_id = OLD.id;
    END;
`

// ListCustom satisfies Store.ListCustom.
func (s *SQLiteStore) ListCustom() ([]Definition, error) {
	rows, err := s.db.Query(
		`SELECT id, display_name, description, detect_binary,
		        check_playbook, apply_playbook, check_only,
		        created_by, created_at, updated_at, deleted_at
		 FROM updater_definitions
		 WHERE deleted_at IS NULL
		 ORDER BY display_name COLLATE NOCASE, id`,
	)
	if err != nil {
		return nil, fmt.Errorf("updaters: list custom: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Definition{}
	for rows.Next() {
		d, err := scanDef(rows)
		if err != nil {
			return nil, fmt.Errorf("updaters: scan: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetCustom satisfies Store.GetCustom.
func (s *SQLiteStore) GetCustom(id string) (Definition, error) {
	row := s.db.QueryRow(
		`SELECT id, display_name, description, detect_binary,
		        check_playbook, apply_playbook, check_only,
		        created_by, created_at, updated_at, deleted_at
		 FROM updater_definitions
		 WHERE id = ?`,
		id,
	)
	d, err := scanDef(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Definition{}, ErrNotFound
	}
	return d, err
}

// CreateCustom satisfies Store.CreateCustom.
func (s *SQLiteStore) CreateCustom(d Definition) (Definition, error) {
	if !IsCustomID(d.ID) {
		return Definition{}, fmt.Errorf("%w: custom id must begin with %q", ErrReservedID, PrefixCustom)
	}
	if err := d.Validate(); err != nil {
		return Definition{}, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	now := s.Now().UTC()
	d.CreatedAt = now
	d.UpdatedAt = now
	d.DeletedAt = nil
	_, err := s.db.Exec(
		`INSERT INTO updater_definitions
			(id, display_name, description, detect_binary,
			 check_playbook, apply_playbook, check_only,
			 created_by, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		d.ID, d.DisplayName, d.Description, d.DetectBinary,
		string(d.CheckPlaybook), string(d.ApplyPlaybook), boolToInt(d.CheckOnly),
		d.CreatedBy, now.UnixNano(), now.UnixNano(),
	)
	if err != nil {
		// SQLite reports duplicate-PK as "UNIQUE constraint failed" —
		// translate so handlers can branch cleanly.
		if isUniqueErr(err) {
			return Definition{}, ErrDuplicate
		}
		return Definition{}, fmt.Errorf("updaters: insert custom: %w", err)
	}
	return d, nil
}

// UpdateCustom satisfies Store.UpdateCustom.
func (s *SQLiteStore) UpdateCustom(d Definition) (Definition, error) {
	if !IsCustomID(d.ID) {
		return Definition{}, fmt.Errorf("%w: custom id must begin with %q", ErrReservedID, PrefixCustom)
	}
	if err := d.Validate(); err != nil {
		return Definition{}, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	existing, err := s.GetCustom(d.ID)
	if err != nil {
		return Definition{}, err
	}
	if existing.IsDeleted() {
		return Definition{}, ErrNotFound
	}
	now := s.Now().UTC()
	d.CreatedBy = existing.CreatedBy
	d.CreatedAt = existing.CreatedAt
	d.UpdatedAt = now
	d.DeletedAt = nil
	if _, err := s.db.Exec(
		`UPDATE updater_definitions SET
			display_name = ?,
			description = ?,
			detect_binary = ?,
			check_playbook = ?,
			apply_playbook = ?,
			check_only = ?,
			updated_at = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		d.DisplayName, d.Description, d.DetectBinary,
		string(d.CheckPlaybook), string(d.ApplyPlaybook), boolToInt(d.CheckOnly),
		now.UnixNano(), d.ID,
	); err != nil {
		return Definition{}, fmt.Errorf("updaters: update custom: %w", err)
	}
	return d, nil
}

// DeleteCustom satisfies Store.DeleteCustom.
func (s *SQLiteStore) DeleteCustom(id string, at time.Time) error {
	res, err := s.db.Exec(
		`UPDATE updater_definitions
		 SET deleted_at = ?, updated_at = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		at.UTC().UnixNano(), at.UTC().UnixNano(), id,
	)
	if err != nil {
		return fmt.Errorf("updaters: delete custom: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("updaters: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertAvailability satisfies Store.UpsertAvailability. Uses
// SQLite's ON CONFLICT shorthand so the row is created or its
// last_seen_at refreshed in one statement. The enabled flag is
// only set on insert (default 1); update keeps whatever the
// operator chose so a re-inspection doesn't quietly flip an
// explicit disable back on.
func (s *SQLiteStore) UpsertAvailability(systemID, updaterID string, at time.Time) error {
	if strings.TrimSpace(systemID) == "" || strings.TrimSpace(updaterID) == "" {
		return fmt.Errorf("%w: system_id and updater_id required", ErrInvalid)
	}
	_, err := s.db.Exec(
		`INSERT INTO system_updaters (system_id, updater_id, last_seen_at, enabled)
		 VALUES (?, ?, ?, 1)
		 ON CONFLICT (system_id, updater_id) DO UPDATE SET
			last_seen_at = excluded.last_seen_at`,
		systemID, updaterID, at.UTC().UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("updaters: upsert availability: %w", err)
	}
	return nil
}

// SetEnabled satisfies Store.SetEnabled.
func (s *SQLiteStore) SetEnabled(systemID, updaterID string, enabled bool) error {
	if strings.TrimSpace(systemID) == "" || strings.TrimSpace(updaterID) == "" {
		return fmt.Errorf("%w: system_id and updater_id required", ErrInvalid)
	}
	flag := 0
	if enabled {
		flag = 1
	}
	res, err := s.db.Exec(
		`UPDATE system_updaters SET enabled = ? WHERE system_id = ? AND updater_id = ?`,
		flag, systemID, updaterID,
	)
	if err != nil {
		return fmt.Errorf("updaters: set enabled: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("updaters: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveAvailability satisfies Store.RemoveAvailability.
func (s *SQLiteStore) RemoveAvailability(systemID, updaterID string) error {
	if _, err := s.db.Exec(
		`DELETE FROM system_updaters WHERE system_id = ? AND updater_id = ?`,
		systemID, updaterID,
	); err != nil {
		return fmt.Errorf("updaters: remove availability: %w", err)
	}
	return nil
}

// AvailabilityFor satisfies Store.AvailabilityFor.
func (s *SQLiteStore) AvailabilityFor(systemID string) ([]Availability, error) {
	rows, err := s.db.Query(
		`SELECT system_id, updater_id, last_seen_at, enabled, pending_packages
		 FROM system_updaters
		 WHERE system_id = ?
		 ORDER BY updater_id`,
		systemID,
	)
	if err != nil {
		return nil, fmt.Errorf("updaters: availability for: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Availability{}
	for rows.Next() {
		var a Availability
		var lastSeen sql.NullInt64
		var enabled int
		var pending string
		if err := rows.Scan(&a.SystemID, &a.UpdaterID, &lastSeen, &enabled, &pending); err != nil {
			return nil, fmt.Errorf("updaters: scan availability: %w", err)
		}
		if lastSeen.Valid {
			t := time.Unix(0, lastSeen.Int64).UTC()
			a.LastSeenAt = &t
		}
		a.Enabled = enabled != 0
		a.PendingPackages = decodePendingPackages(pending)
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetPendingPackages satisfies Store.SetPendingPackages. The
// caller's slice is JSON-encoded so SQLite stores a single TEXT
// column; nil and empty inputs both serialize to `[]` for a
// consistent decode on the read path.
func (s *SQLiteStore) SetPendingPackages(systemID, updaterID string, packages []PendingPackage) error {
	if strings.TrimSpace(systemID) == "" || strings.TrimSpace(updaterID) == "" {
		return fmt.Errorf("%w: system_id and updater_id required", ErrInvalid)
	}
	encoded, err := encodePendingPackages(packages)
	if err != nil {
		return fmt.Errorf("updaters: encode pending packages: %w", err)
	}
	_, err = s.db.Exec(
		`UPDATE system_updaters SET pending_packages = ? WHERE system_id = ? AND updater_id = ?`,
		encoded, systemID, updaterID,
	)
	if err != nil {
		return fmt.Errorf("updaters: set pending packages: %w", err)
	}
	return nil
}

// InsertRun satisfies Store.InsertRun. The caller assigns the id
// (so the audit-start row can share it).
func (s *SQLiteStore) InsertRun(r Run) error {
	if !r.Kind.IsValid() {
		return fmt.Errorf("%w: run kind", ErrInvalid)
	}
	if r.ID == "" || r.SystemID == "" {
		return fmt.Errorf("%w: run id and system_id required", ErrInvalid)
	}
	_, err := s.db.Exec(
		`INSERT INTO updater_runs
			(id, system_id, updater_id, kind, started_at, actor_id, playbook_sha, log_tail)
		 VALUES (?, ?, ?, ?, ?, ?, ?, '')`,
		r.ID, r.SystemID, r.UpdaterID, string(r.Kind),
		r.StartedAt.UTC().UnixNano(), r.ActorID, r.PlaybookSHA,
	)
	if err != nil {
		return fmt.Errorf("updaters: insert run: %w", err)
	}
	return nil
}

// TrimRunsForSystem satisfies Store.TrimRunsForSystem. The DELETE
// uses a window on started_at via a correlated subquery so we keep
// the most recent `keep` rows across every (updater, kind) for the
// system — a sloppy operator running Check ten times in a row
// won't push their last Apply off the bottom.
func (s *SQLiteStore) TrimRunsForSystem(systemID string, keep int) error {
	if systemID == "" {
		return fmt.Errorf("%w: system_id required", ErrInvalid)
	}
	if keep <= 0 {
		return nil
	}
	_, err := s.db.Exec(
		`DELETE FROM updater_runs
		 WHERE system_id = ?
		   AND id NOT IN (
		       SELECT id FROM updater_runs
		       WHERE system_id = ?
		       ORDER BY started_at DESC
		       LIMIT ?
		   )`,
		systemID, systemID, keep,
	)
	if err != nil {
		return fmt.Errorf("updaters: trim runs: %w", err)
	}
	return nil
}

// FinishRun satisfies Store.FinishRun. log_tail is truncated to
// MaxLogTailBytes at write time so a chatty playbook cannot fill
// the DB.
func (s *SQLiteStore) FinishRun(id string, finishedAt time.Time, exitCode, affectedCount int, logTail string) error {
	if len(logTail) > MaxLogTailBytes {
		logTail = logTail[len(logTail)-MaxLogTailBytes:]
	}
	res, err := s.db.Exec(
		`UPDATE updater_runs
		 SET finished_at = ?, exit_code = ?, affected_count = ?, log_tail = ?
		 WHERE id = ?`,
		finishedAt.UTC().UnixNano(), exitCode, affectedCount, logTail, id,
	)
	if err != nil {
		return fmt.Errorf("updaters: finish run: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("updaters: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SystemStatsAll satisfies Store.SystemStatsAll. Two passes:
//  1. MAX(started_at) per system across check runs powers Last
//     Checked. Apply and inspect runs deliberately don't count —
//     "Last Checked" means "last time we asked what's pending."
//  2. For Updates Available, sum affected_count from each
//     system's latest check run per updater. The window-function
//     subquery pins to the newest finished_at; rows where a check
//     is still in-flight don't contribute until they land.
//
// The two queries return the same key set in the same map so
// callers can rely on missing keys meaning "no check has run."
func (s *SQLiteStore) SystemStatsAll() (map[string]SystemStats, error) {
	out := map[string]SystemStats{}

	lastRows, err := s.db.Query(
		`SELECT system_id, MAX(started_at)
		 FROM updater_runs
		 WHERE kind = 'check'
		 GROUP BY system_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("updaters: stats last-checked: %w", err)
	}
	defer func() { _ = lastRows.Close() }()
	for lastRows.Next() {
		var sysID string
		var ts int64
		if err := lastRows.Scan(&sysID, &ts); err != nil {
			return nil, fmt.Errorf("updaters: stats scan last-checked: %w", err)
		}
		t := time.Unix(0, ts).UTC()
		stats := out[sysID]
		stats.LastCheckedAt = &t
		out[sysID] = stats
	}
	if err := lastRows.Err(); err != nil {
		return nil, fmt.Errorf("updaters: stats last-checked rows: %w", err)
	}

	pendingRows, err := s.db.Query(
		`SELECT system_id, SUM(affected_count) FROM (
		     SELECT r1.system_id, r1.updater_id, r1.affected_count
		     FROM updater_runs r1
		     WHERE r1.kind = 'check'
		       AND r1.finished_at IS NOT NULL
		       AND r1.finished_at = (
		           SELECT MAX(r2.finished_at) FROM updater_runs r2
		           WHERE r2.system_id = r1.system_id
		             AND r2.updater_id = r1.updater_id
		             AND r2.kind = 'check'
		             AND r2.finished_at IS NOT NULL
		       )
		 ) latest
		 GROUP BY system_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("updaters: stats pending: %w", err)
	}
	defer func() { _ = pendingRows.Close() }()
	for pendingRows.Next() {
		var sysID string
		var pending int
		if err := pendingRows.Scan(&sysID, &pending); err != nil {
			return nil, fmt.Errorf("updaters: stats scan pending: %w", err)
		}
		stats := out[sysID]
		stats.PendingUpdates = pending
		out[sysID] = stats
	}
	if err := pendingRows.Err(); err != nil {
		return nil, fmt.Errorf("updaters: stats pending rows: %w", err)
	}

	// Union of per-(system, updater) pending_packages, scoped per
	// system. Two-pass aggregation in Go avoids leaning on SQLite
	// JSON1 (which is available in modernc but adds a coupling we
	// don't otherwise need). De-dupe on the full (Name, OldVersion,
	// NewVersion) triple and sort so callers get a stable order
	// without re-sorting on the SPA side.
	packageRows, err := s.db.Query(
		`SELECT system_id, pending_packages FROM system_updaters
		 WHERE pending_packages != '[]' AND pending_packages != ''`,
	)
	if err != nil {
		return nil, fmt.Errorf("updaters: stats packages: %w", err)
	}
	defer func() { _ = packageRows.Close() }()
	bySys := map[string]map[PendingPackage]bool{}
	for packageRows.Next() {
		var sysID, raw string
		if err := packageRows.Scan(&sysID, &raw); err != nil {
			return nil, fmt.Errorf("updaters: stats scan packages: %w", err)
		}
		set := bySys[sysID]
		if set == nil {
			set = map[PendingPackage]bool{}
			bySys[sysID] = set
		}
		for _, p := range decodePendingPackages(raw) {
			set[p] = true
		}
	}
	if err := packageRows.Err(); err != nil {
		return nil, fmt.Errorf("updaters: stats packages rows: %w", err)
	}
	for sysID, set := range bySys {
		pkgs := make([]PendingPackage, 0, len(set))
		for p := range set {
			pkgs = append(pkgs, p)
		}
		sort.Slice(pkgs, func(i, j int) bool {
			if pkgs[i].Name != pkgs[j].Name {
				return pkgs[i].Name < pkgs[j].Name
			}
			if pkgs[i].OldVersion != pkgs[j].OldVersion {
				return pkgs[i].OldVersion < pkgs[j].OldVersion
			}
			return pkgs[i].NewVersion < pkgs[j].NewVersion
		})
		stats := out[sysID]
		stats.PendingPackages = pkgs
		out[sysID] = stats
	}

	// Most-recent terminated run per system. Order on finished_at
	// descending and take the head; any non-zero exit code flips
	// LastRunFailed. In-flight runs (finished_at IS NULL) are
	// deliberately skipped so a still-running check doesn't show
	// red — the row is back to normal once it terminates.
	lastRunRows, err := s.db.Query(
		`SELECT r1.system_id, r1.kind, r1.exit_code
		 FROM updater_runs r1
		 WHERE r1.finished_at IS NOT NULL
		   AND r1.finished_at = (
		       SELECT MAX(r2.finished_at) FROM updater_runs r2
		       WHERE r2.system_id = r1.system_id
		         AND r2.finished_at IS NOT NULL
		   )`,
	)
	if err != nil {
		return nil, fmt.Errorf("updaters: stats last-run: %w", err)
	}
	defer func() { _ = lastRunRows.Close() }()
	for lastRunRows.Next() {
		var sysID, kind string
		var exit sql.NullInt64
		if err := lastRunRows.Scan(&sysID, &kind, &exit); err != nil {
			return nil, fmt.Errorf("updaters: stats scan last-run: %w", err)
		}
		if exit.Valid && exit.Int64 != 0 {
			stats := out[sysID]
			stats.LastRunFailed = true
			stats.LastRunReason = fmt.Sprintf("%s exit %d", kind, exit.Int64)
			out[sysID] = stats
		}
	}
	if err := lastRunRows.Err(); err != nil {
		return nil, fmt.Errorf("updaters: stats last-run rows: %w", err)
	}

	// Any system_id present in system_action_locks has an in-flight
	// run. Insert into the map if missing so a brand-new system on
	// its first Inspect (no prior runs, no row in `out` yet) still
	// surfaces Running=true.
	lockRows, err := s.db.Query(`SELECT DISTINCT system_id FROM system_action_locks`)
	if err != nil {
		return nil, fmt.Errorf("updaters: stats running: %w", err)
	}
	defer func() { _ = lockRows.Close() }()
	for lockRows.Next() {
		var sysID string
		if err := lockRows.Scan(&sysID); err != nil {
			return nil, fmt.Errorf("updaters: stats scan running: %w", err)
		}
		stats := out[sysID]
		stats.Running = true
		out[sysID] = stats
	}
	return out, lockRows.Err()
}

// ListRuns satisfies Store.ListRuns.
func (s *SQLiteStore) ListRuns(systemID string, limit int) ([]Run, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, system_id, updater_id, kind, started_at,
		        finished_at, exit_code, affected_count, actor_id, playbook_sha, log_tail
		 FROM updater_runs
		 WHERE system_id = ?
		 ORDER BY started_at DESC
		 LIMIT ?`,
		systemID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("updaters: list runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("updaters: scan run: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AcquireLock satisfies Store.AcquireLock. Returns ErrConflict if a
// row already exists for systemID; the caller can use
// ConflictingRun to surface which run holds it.
func (s *SQLiteStore) AcquireLock(systemID, runID string, at time.Time) error {
	if systemID == "" || runID == "" {
		return fmt.Errorf("%w: system_id and run_id required", ErrInvalid)
	}
	_, err := s.db.Exec(
		`INSERT INTO system_action_locks (system_id, run_id, acquired_at)
		 VALUES (?, ?, ?)`,
		systemID, runID, at.UTC().UnixNano(),
	)
	if err != nil {
		if isUniqueErr(err) {
			return ErrConflict
		}
		return fmt.Errorf("updaters: acquire lock: %w", err)
	}
	return nil
}

// ReleaseLock satisfies Store.ReleaseLock. Idempotent — a missing
// row is treated as success.
func (s *SQLiteStore) ReleaseLock(systemID, runID string) error {
	if _, err := s.db.Exec(
		`DELETE FROM system_action_locks WHERE system_id = ? AND run_id = ?`,
		systemID, runID,
	); err != nil {
		return fmt.Errorf("updaters: release lock: %w", err)
	}
	return nil
}

// ConflictingRun satisfies Store.ConflictingRun.
func (s *SQLiteStore) ConflictingRun(systemID string) (string, error) {
	var id string
	err := s.db.QueryRow(
		`SELECT run_id FROM system_action_locks WHERE system_id = ?`,
		systemID,
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("updaters: conflicting run: %w", err)
	}
	return id, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanDef(s scanner) (Definition, error) {
	var (
		d         Definition
		checkBody string
		applyBody string
		checkOnly int
		createdAt int64
		updatedAt int64
		deletedAt sql.NullInt64
	)
	if err := s.Scan(
		&d.ID, &d.DisplayName, &d.Description, &d.DetectBinary,
		&checkBody, &applyBody, &checkOnly,
		&d.CreatedBy, &createdAt, &updatedAt, &deletedAt,
	); err != nil {
		return Definition{}, err
	}
	d.Source = SourceCustom
	d.CheckPlaybook = []byte(checkBody)
	d.ApplyPlaybook = []byte(applyBody)
	d.CheckOnly = checkOnly != 0
	d.CreatedAt = time.Unix(0, createdAt).UTC()
	d.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if deletedAt.Valid {
		t := time.Unix(0, deletedAt.Int64).UTC()
		d.DeletedAt = &t
	}
	return d, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func scanRun(s scanner) (Run, error) {
	var (
		r          Run
		updaterID  string
		startedAt  int64
		finishedAt sql.NullInt64
		exitCode   sql.NullInt64
		affected   int
		kind       string
	)
	if err := s.Scan(
		&r.ID, &r.SystemID, &updaterID, &kind, &startedAt,
		&finishedAt, &exitCode, &affected, &r.ActorID, &r.PlaybookSHA, &r.LogTail,
	); err != nil {
		return Run{}, err
	}
	r.UpdaterID = updaterID
	r.Kind = RunKind(kind)
	r.StartedAt = time.Unix(0, startedAt).UTC()
	if finishedAt.Valid {
		t := time.Unix(0, finishedAt.Int64).UTC()
		r.FinishedAt = &t
	}
	if exitCode.Valid {
		ec := int(exitCode.Int64)
		r.ExitCode = &ec
	}
	r.AffectedCount = affected
	return r, nil
}

// isUniqueErr matches SQLite's "UNIQUE constraint failed" wrapped
// through database/sql. Coarse string-match is intentional: the
// modernc driver returns the message in the err's Error() string
// and the test for it is the same approach hostkeys uses.
func isUniqueErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// encodePendingPackages JSON-encodes the slice for SQLite storage.
// nil and empty both round-trip to `[]` so the read path returns
// an empty slice rather than nil.
func encodePendingPackages(pkgs []PendingPackage) (string, error) {
	if pkgs == nil {
		pkgs = []PendingPackage{}
	}
	b, err := json.Marshal(pkgs)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// decodePendingPackages turns the stored TEXT back into a slice.
// Accepts both the current `[{name,oldVersion,newVersion}]` shape
// and the legacy `["name", ...]` shape from databases written
// before the per-package version columns landed — legacy entries
// surface as PendingPackage{Name: s} with empty versions, and the
// next successful Check overwrites the row in the new shape. Empty
// / invalid input returns an empty (non-nil) slice so callers
// never have to nil-check the field.
func decodePendingPackages(raw string) []PendingPackage {
	if raw == "" {
		return []PendingPackage{}
	}
	var pkgs []PendingPackage
	if err := json.Unmarshal([]byte(raw), &pkgs); err == nil {
		return pkgs
	}
	var names []string
	if err := json.Unmarshal([]byte(raw), &names); err != nil {
		return []PendingPackage{}
	}
	out := make([]PendingPackage, 0, len(names))
	for _, n := range names {
		out = append(out, PendingPackage{Name: n})
	}
	return out
}
