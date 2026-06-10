// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Store is the persistence boundary for custom exporter definitions,
// per-system installer state, per-system settings, and run history.
// SQLiteStore is the production implementation.
type Store interface {
	// ListCustom returns every non-deleted custom exporter definition.
	// Soft-deleted rows are excluded — see GetCustom for the
	// audit/history retrieval path.
	ListCustom() ([]Definition, error)
	// GetCustom returns one custom definition by id. Returns
	// soft-deleted rows so audit and run-history lookups can render
	// the historical name.
	GetCustom(id string) (Definition, error)
	// CreateCustom inserts a new custom definition. Returns
	// ErrDuplicate when the id is already taken (including by a
	// tombstoned row).
	CreateCustom(d Definition) (Definition, error)
	// UpdateCustom rewrites the mutable fields of an existing
	// non-deleted custom definition. Returns ErrNotFound when the id
	// is unknown or already soft-deleted.
	UpdateCustom(d Definition) (Definition, error)
	// DeleteCustom soft-deletes the row by stamping deleted_at.
	DeleteCustom(id string, at time.Time) error

	// SystemExporter operations.
	UpsertSystemExporter(row SystemExporter) error
	GetSystemExporter(systemID, exporterID string) (SystemExporter, error)
	ListSystemExporters(systemID string) ([]SystemExporter, error)
	MarkRemoved(systemID, exporterID string, at time.Time, reason string) error
	// SetScrapeEnabled flips the operator-controlled scrape toggle on
	// an existing (system, exporter) row. Returns ErrNotFound when the
	// row doesn't exist (install must have happened first). Returns
	// the row state in the bool: true if the value actually changed,
	// false if it was already at the requested value (idempotent
	// caller).
	SetScrapeEnabled(systemID, exporterID string, enabled bool) (changed bool, err error)

	// Settings — auto-creates a default row on first read so the
	// handler can rely on ScrapeLocalhost in the absence of any
	// operator interaction.
	GetSettings(systemID string) (SystemSettings, error)
	SetScrapeMode(systemID string, mode ScrapeMode) error

	// Runs.
	InsertRun(r Run) error
	FinishRun(id string, finishedAt time.Time, exitCode int, logTail string) error
	ListRuns(systemID string, limit int) ([]Run, error)
	TrimRunsForSystem(systemID string, keep int) error
	// ReconcileOrphanedRuns finalizes every exporter run a previous
	// process left in flight (finished_at IS NULL) as an interrupted
	// failure. Called once at startup; the shared advisory locks are
	// cleared by the updater store. Returns the number finalized.
	ReconcileOrphanedRuns(at time.Time) (int, error)
}

// SQLiteStore persists exporter state.
type SQLiteStore struct {
	db *sql.DB

	NewID func() string
	Now   func() time.Time
}

// NewSQLiteStore migrates the schema and returns a ready store.
// Idempotent across boots.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("exporters: schema: %w", err)
	}
	if err := addScrapeEnabledColumn(db); err != nil {
		return nil, fmt.Errorf("exporters: migrate scrape_enabled: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

// addScrapeEnabledColumn brings databases predating the per-row
// "Prometheus is scraping this entry" toggle up to schema. Pragma-probe
// pattern shared with the rest of the tree; defaults to 1 so existing
// rows keep being scraped (the only path to 0 is the operator hitting
// the pause Switch).
func addScrapeEnabledColumn(db *sql.DB) error {
	row := db.QueryRow(`SELECT 1 FROM pragma_table_info('system_exporters') WHERE name = 'scrape_enabled'`)
	var found int
	switch err := row.Scan(&found); {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		_, err := db.Exec(`ALTER TABLE system_exporters ADD COLUMN scrape_enabled INTEGER NOT NULL DEFAULT 1`)
		return err
	default:
		return err
	}
}

// schema covers the four exporter tables. Cascade triggers on hosts
// wipe system_exporters / system_exporter_settings / exporter_runs
// rows when a host is deleted; exporter_definitions are soft-deleted
// so audit/run-history rows still resolve the original name.
const schema = `
CREATE TABLE IF NOT EXISTS exporter_definitions (
    id                     TEXT PRIMARY KEY,
    display_name           TEXT NOT NULL,
    description            TEXT NOT NULL DEFAULT '',
    applies_to_pkg_manager TEXT NOT NULL,
    exporter_kind          TEXT NOT NULL CHECK (exporter_kind IN ('node_exporter', 'windows_exporter')),
    bind_port              INTEGER NOT NULL DEFAULT 9100,
    install_playbook       TEXT NOT NULL,
    status_playbook        TEXT NOT NULL,
    remove_playbook        TEXT NOT NULL DEFAULT '',
    created_by             TEXT NOT NULL DEFAULT '',
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    deleted_at             INTEGER
) STRICT;

CREATE TABLE IF NOT EXISTS system_exporters (
    system_id        TEXT NOT NULL,
    exporter_id      TEXT NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('installed', 'running', 'failed', 'removed')),
    port             INTEGER NOT NULL DEFAULT 0,
    service_name     TEXT NOT NULL DEFAULT '',
    last_status_at   INTEGER,
    last_install_at  INTEGER,
    last_reason      TEXT NOT NULL DEFAULT '',
    scrape_enabled   INTEGER NOT NULL DEFAULT 1 CHECK (scrape_enabled IN (0, 1)),
    PRIMARY KEY (system_id, exporter_id)
) STRICT;

CREATE TABLE IF NOT EXISTS system_exporter_settings (
    system_id    TEXT PRIMARY KEY,
    scrape_mode  TEXT NOT NULL DEFAULT 'localhost' CHECK (scrape_mode IN ('localhost', 'mtls-self', 'mtls-byo'))
) STRICT;

CREATE TABLE IF NOT EXISTS exporter_runs (
    id           TEXT PRIMARY KEY,
    system_id    TEXT NOT NULL,
    exporter_id  TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('install', 'status', 'remove')),
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER,
    exit_code    INTEGER,
    actor_id     TEXT NOT NULL DEFAULT '',
    playbook_sha TEXT NOT NULL DEFAULT '',
    log_tail     TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX IF NOT EXISTS exporter_runs_system   ON exporter_runs(system_id, started_at DESC);
CREATE INDEX IF NOT EXISTS exporter_runs_exporter ON exporter_runs(exporter_id, started_at DESC);

CREATE TRIGGER IF NOT EXISTS exporter_runs_cleanup_host
    AFTER DELETE ON hosts
    FOR EACH ROW
    BEGIN
        DELETE FROM exporter_runs WHERE system_id = OLD.id;
    END;
CREATE TRIGGER IF NOT EXISTS system_exporters_cleanup_host
    AFTER DELETE ON hosts
    FOR EACH ROW
    BEGIN
        DELETE FROM system_exporters WHERE system_id = OLD.id;
    END;
CREATE TRIGGER IF NOT EXISTS system_exporter_settings_cleanup_host
    AFTER DELETE ON hosts
    FOR EACH ROW
    BEGIN
        DELETE FROM system_exporter_settings WHERE system_id = OLD.id;
    END;
`

// ListCustom satisfies Store.ListCustom.
func (s *SQLiteStore) ListCustom() ([]Definition, error) {
	rows, err := s.db.Query(
		`SELECT id, display_name, description, applies_to_pkg_manager,
		        exporter_kind, bind_port,
		        install_playbook, status_playbook, remove_playbook,
		        created_by, created_at, updated_at, deleted_at
		 FROM exporter_definitions
		 WHERE deleted_at IS NULL
		 ORDER BY display_name COLLATE NOCASE, id`,
	)
	if err != nil {
		return nil, fmt.Errorf("exporters: list custom: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Definition{}
	for rows.Next() {
		d, err := scanDef(rows)
		if err != nil {
			return nil, fmt.Errorf("exporters: scan: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetCustom satisfies Store.GetCustom.
func (s *SQLiteStore) GetCustom(id string) (Definition, error) {
	row := s.db.QueryRow(
		`SELECT id, display_name, description, applies_to_pkg_manager,
		        exporter_kind, bind_port,
		        install_playbook, status_playbook, remove_playbook,
		        created_by, created_at, updated_at, deleted_at
		 FROM exporter_definitions
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
		`INSERT INTO exporter_definitions
			(id, display_name, description, applies_to_pkg_manager,
			 exporter_kind, bind_port,
			 install_playbook, status_playbook, remove_playbook,
			 created_by, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		d.ID, d.DisplayName, d.Description, d.AppliesToPkgManager,
		string(d.ExporterKind), d.BindPort,
		string(d.InstallPlaybook), string(d.StatusPlaybook), string(d.RemovePlaybook),
		d.CreatedBy, now.UnixNano(), now.UnixNano(),
	)
	if err != nil {
		if isUniqueErr(err) {
			return Definition{}, ErrDuplicate
		}
		return Definition{}, fmt.Errorf("exporters: insert custom: %w", err)
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
		`UPDATE exporter_definitions SET
			display_name = ?,
			description = ?,
			applies_to_pkg_manager = ?,
			exporter_kind = ?,
			bind_port = ?,
			install_playbook = ?,
			status_playbook = ?,
			remove_playbook = ?,
			updated_at = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		d.DisplayName, d.Description, d.AppliesToPkgManager,
		string(d.ExporterKind), d.BindPort,
		string(d.InstallPlaybook), string(d.StatusPlaybook), string(d.RemovePlaybook),
		now.UnixNano(), d.ID,
	); err != nil {
		return Definition{}, fmt.Errorf("exporters: update custom: %w", err)
	}
	return d, nil
}

// DeleteCustom satisfies Store.DeleteCustom.
func (s *SQLiteStore) DeleteCustom(id string, at time.Time) error {
	res, err := s.db.Exec(
		`UPDATE exporter_definitions
		 SET deleted_at = ?, updated_at = ?
		 WHERE id = ? AND deleted_at IS NULL`,
		at.UTC().UnixNano(), at.UTC().UnixNano(), id,
	)
	if err != nil {
		return fmt.Errorf("exporters: delete custom: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("exporters: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertSystemExporter satisfies Store.UpsertSystemExporter. Used by
// the runner after install / status / restart to refresh the live
// view of (system, exporter) state.
func (s *SQLiteStore) UpsertSystemExporter(row SystemExporter) error {
	if strings.TrimSpace(row.SystemID) == "" || strings.TrimSpace(row.ExporterID) == "" {
		return fmt.Errorf("%w: system_id and exporter_id required", ErrInvalid)
	}
	if !row.State.IsValid() {
		return fmt.Errorf("%w: invalid state %q", ErrInvalid, string(row.State))
	}
	var lastStatus, lastInstall sql.NullInt64
	if row.LastStatusAt != nil {
		lastStatus.Valid = true
		lastStatus.Int64 = row.LastStatusAt.UTC().UnixNano()
	}
	if row.LastInstallAt != nil {
		lastInstall.Valid = true
		lastInstall.Int64 = row.LastInstallAt.UTC().UnixNano()
	}
	// Manual two-step upsert keeps last_install_at sticky — a status
	// row shouldn't blow away the install timestamp. Existing row
	// fields are reused if the upsert's value is the zero/empty form.
	// scrape_enabled is operator-controlled and intentionally NOT in
	// the UPDATE SET — new rows get the schema default (1); existing
	// rows keep whatever the operator last set via the Scrape toggle.
	_, err := s.db.Exec(
		`INSERT INTO system_exporters
			(system_id, exporter_id, state, port, service_name,
			 last_status_at, last_install_at, last_reason)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (system_id, exporter_id) DO UPDATE SET
			state           = excluded.state,
			port            = excluded.port,
			service_name    = excluded.service_name,
			last_status_at  = COALESCE(excluded.last_status_at,  system_exporters.last_status_at),
			last_install_at = COALESCE(excluded.last_install_at, system_exporters.last_install_at),
			last_reason     = excluded.last_reason`,
		row.SystemID, row.ExporterID, string(row.State), row.Port, row.ServiceName,
		lastStatus, lastInstall, row.LastReason,
	)
	if err != nil {
		return fmt.Errorf("exporters: upsert system_exporter: %w", err)
	}
	return nil
}

// GetSystemExporter satisfies Store.GetSystemExporter.
func (s *SQLiteStore) GetSystemExporter(systemID, exporterID string) (SystemExporter, error) {
	row := s.db.QueryRow(
		`SELECT system_id, exporter_id, state, port, service_name,
		        last_status_at, last_install_at, last_reason, scrape_enabled
		 FROM system_exporters
		 WHERE system_id = ? AND exporter_id = ?`,
		systemID, exporterID,
	)
	r, err := scanSystemExporter(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SystemExporter{}, ErrNotFound
	}
	return r, err
}

// ListSystemExporters satisfies Store.ListSystemExporters.
func (s *SQLiteStore) ListSystemExporters(systemID string) ([]SystemExporter, error) {
	rows, err := s.db.Query(
		`SELECT system_id, exporter_id, state, port, service_name,
		        last_status_at, last_install_at, last_reason, scrape_enabled
		 FROM system_exporters
		 WHERE system_id = ?
		 ORDER BY exporter_id`,
		systemID,
	)
	if err != nil {
		return nil, fmt.Errorf("exporters: list system_exporters: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []SystemExporter{}
	for rows.Next() {
		r, err := scanSystemExporter(rows)
		if err != nil {
			return nil, fmt.Errorf("exporters: scan system_exporter: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetScrapeEnabled flips the operator-controlled scrape toggle.
// Returns (true, nil) when the value actually changed, (false, nil)
// when the value already matched (idempotent caller), or (false,
// ErrNotFound) when no row exists for (systemID, exporterID). The
// targets.json writer filters by scrape_enabled = 1 so a flip
// immediately drops the entry from Prometheus's scrape set.
func (s *SQLiteStore) SetScrapeEnabled(systemID, exporterID string, enabled bool) (bool, error) {
	want := 0
	if enabled {
		want = 1
	}
	res, err := s.db.Exec(
		`UPDATE system_exporters SET scrape_enabled = ?
		 WHERE system_id = ? AND exporter_id = ? AND scrape_enabled != ?`,
		want, systemID, exporterID, want,
	)
	if err != nil {
		return false, fmt.Errorf("exporters: set scrape_enabled: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("exporters: rows affected: %w", err)
	}
	if n > 0 {
		return true, nil
	}
	// No row was flipped — either the row doesn't exist or the value
	// already matched. Distinguish via a probe.
	var probed int
	switch err := s.db.QueryRow(
		`SELECT 1 FROM system_exporters WHERE system_id = ? AND exporter_id = ?`,
		systemID, exporterID,
	).Scan(&probed); {
	case errors.Is(err, sql.ErrNoRows):
		return false, ErrNotFound
	case err != nil:
		return false, fmt.Errorf("exporters: scrape_enabled probe: %w", err)
	}
	return false, nil
}

// MarkRemoved flips an existing row to state=removed without
// blowing away the install / status timestamps so the operator
// retains the history of "this used to be installed."
func (s *SQLiteStore) MarkRemoved(systemID, exporterID string, at time.Time, reason string) error {
	res, err := s.db.Exec(
		`UPDATE system_exporters
		 SET state = 'removed', last_status_at = ?, last_reason = ?
		 WHERE system_id = ? AND exporter_id = ?`,
		at.UTC().UnixNano(), reason, systemID, exporterID,
	)
	if err != nil {
		return fmt.Errorf("exporters: mark removed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("exporters: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetSettings satisfies Store.GetSettings — returns the default
// (ScrapeLocalhost) row when none exists yet without writing.
func (s *SQLiteStore) GetSettings(systemID string) (SystemSettings, error) {
	row := s.db.QueryRow(
		`SELECT system_id, scrape_mode FROM system_exporter_settings WHERE system_id = ?`,
		systemID,
	)
	var out SystemSettings
	var mode string
	err := row.Scan(&out.SystemID, &mode)
	if errors.Is(err, sql.ErrNoRows) {
		return SystemSettings{SystemID: systemID, ScrapeMode: ScrapeLocalhost}, nil
	}
	if err != nil {
		return SystemSettings{}, fmt.Errorf("exporters: get settings: %w", err)
	}
	out.ScrapeMode = ScrapeMode(mode)
	if !out.ScrapeMode.IsValid() {
		out.ScrapeMode = ScrapeLocalhost
	}
	return out, nil
}

// SetScrapeMode satisfies Store.SetScrapeMode. Upserts so the
// first interaction creates the row.
func (s *SQLiteStore) SetScrapeMode(systemID string, mode ScrapeMode) error {
	if strings.TrimSpace(systemID) == "" {
		return fmt.Errorf("%w: system_id required", ErrInvalid)
	}
	if !mode.IsValid() {
		return fmt.Errorf("%w: invalid scrape mode %q", ErrInvalid, string(mode))
	}
	_, err := s.db.Exec(
		`INSERT INTO system_exporter_settings (system_id, scrape_mode)
		 VALUES (?, ?)
		 ON CONFLICT (system_id) DO UPDATE SET scrape_mode = excluded.scrape_mode`,
		systemID, string(mode),
	)
	if err != nil {
		return fmt.Errorf("exporters: set scrape mode: %w", err)
	}
	return nil
}

// InsertRun satisfies Store.InsertRun.
func (s *SQLiteStore) InsertRun(r Run) error {
	if !r.Kind.IsValid() {
		return fmt.Errorf("%w: run kind", ErrInvalid)
	}
	if r.ID == "" || r.SystemID == "" {
		return fmt.Errorf("%w: run id and system_id required", ErrInvalid)
	}
	_, err := s.db.Exec(
		`INSERT INTO exporter_runs
			(id, system_id, exporter_id, kind, started_at, actor_id, playbook_sha, log_tail)
		 VALUES (?, ?, ?, ?, ?, ?, ?, '')`,
		r.ID, r.SystemID, r.ExporterID, string(r.Kind),
		r.StartedAt.UTC().UnixNano(), r.ActorID, r.PlaybookSHA,
	)
	if err != nil {
		return fmt.Errorf("exporters: insert run: %w", err)
	}
	return nil
}

// FinishRun satisfies Store.FinishRun. log_tail is truncated to
// MaxLogTailBytes at write time so a chatty playbook cannot fill
// the DB.
func (s *SQLiteStore) FinishRun(id string, finishedAt time.Time, exitCode int, logTail string) error {
	if len(logTail) > MaxLogTailBytes {
		logTail = logTail[len(logTail)-MaxLogTailBytes:]
	}
	res, err := s.db.Exec(
		`UPDATE exporter_runs
		 SET finished_at = ?, exit_code = ?, log_tail = ?
		 WHERE id = ?`,
		finishedAt.UTC().UnixNano(), exitCode, logTail, id,
	)
	if err != nil {
		return fmt.Errorf("exporters: finish run: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("exporters: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// InterruptedExitCode is stamped on an exporter run finalized by
// startup reconciliation; 143 (128 + SIGTERM) is non-zero so the run
// folds into the existing failed rendering.
const InterruptedExitCode = 143

const interruptedLogTail = "Run interrupted: the System Wrangler server restarted while this run was in progress. Its outcome is unknown — re-run the action to get the system's current state."

// ReconcileOrphanedRuns satisfies Store.ReconcileOrphanedRuns.
func (s *SQLiteStore) ReconcileOrphanedRuns(at time.Time) (int, error) {
	res, err := s.db.Exec(
		`UPDATE exporter_runs
		 SET finished_at = ?, exit_code = ?, log_tail = ?
		 WHERE finished_at IS NULL`,
		at.UTC().UnixNano(), InterruptedExitCode, interruptedLogTail,
	)
	if err != nil {
		return 0, fmt.Errorf("exporters: reconcile orphaned runs: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ListRuns satisfies Store.ListRuns.
func (s *SQLiteStore) ListRuns(systemID string, limit int) ([]Run, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(
		`SELECT id, system_id, exporter_id, kind, started_at,
		        finished_at, exit_code, actor_id, playbook_sha, log_tail
		 FROM exporter_runs
		 WHERE system_id = ?
		 ORDER BY started_at DESC
		 LIMIT ?`,
		systemID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("exporters: list runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("exporters: scan run: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TrimRunsForSystem satisfies Store.TrimRunsForSystem.
func (s *SQLiteStore) TrimRunsForSystem(systemID string, keep int) error {
	if systemID == "" {
		return fmt.Errorf("%w: system_id required", ErrInvalid)
	}
	if keep <= 0 {
		return nil
	}
	_, err := s.db.Exec(
		`DELETE FROM exporter_runs
		 WHERE system_id = ?
		   AND id NOT IN (
		       SELECT id FROM exporter_runs
		       WHERE system_id = ?
		       ORDER BY started_at DESC
		       LIMIT ?
		   )`,
		systemID, systemID, keep,
	)
	if err != nil {
		return fmt.Errorf("exporters: trim runs: %w", err)
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanDef(s scanner) (Definition, error) {
	var (
		d             Definition
		install, stat string
		removeBody    string
		kind          string
		createdAt     int64
		updatedAt     int64
		deletedAt     sql.NullInt64
	)
	if err := s.Scan(
		&d.ID, &d.DisplayName, &d.Description, &d.AppliesToPkgManager,
		&kind, &d.BindPort,
		&install, &stat, &removeBody,
		&d.CreatedBy, &createdAt, &updatedAt, &deletedAt,
	); err != nil {
		return Definition{}, err
	}
	d.Source = SourceCustom
	d.ExporterKind = ExporterKind(kind)
	d.InstallPlaybook = []byte(install)
	d.StatusPlaybook = []byte(stat)
	if removeBody != "" {
		d.RemovePlaybook = []byte(removeBody)
	}
	d.CreatedAt = time.Unix(0, createdAt).UTC()
	d.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if deletedAt.Valid {
		t := time.Unix(0, deletedAt.Int64).UTC()
		d.DeletedAt = &t
	}
	return d, nil
}

func scanSystemExporter(s scanner) (SystemExporter, error) {
	var (
		r             SystemExporter
		state         string
		lastStatus    sql.NullInt64
		lastInstall   sql.NullInt64
		scrapeEnabled int
	)
	if err := s.Scan(
		&r.SystemID, &r.ExporterID, &state, &r.Port, &r.ServiceName,
		&lastStatus, &lastInstall, &r.LastReason, &scrapeEnabled,
	); err != nil {
		return SystemExporter{}, err
	}
	r.State = State(state)
	if lastStatus.Valid {
		t := time.Unix(0, lastStatus.Int64).UTC()
		r.LastStatusAt = &t
	}
	if lastInstall.Valid {
		t := time.Unix(0, lastInstall.Int64).UTC()
		r.LastInstallAt = &t
	}
	r.ScrapeEnabled = scrapeEnabled != 0
	return r, nil
}

func scanRun(s scanner) (Run, error) {
	var (
		r          Run
		kind       string
		startedAt  int64
		finishedAt sql.NullInt64
		exitCode   sql.NullInt64
	)
	if err := s.Scan(
		&r.ID, &r.SystemID, &r.ExporterID, &kind, &startedAt,
		&finishedAt, &exitCode, &r.ActorID, &r.PlaybookSHA, &r.LogTail,
	); err != nil {
		return Run{}, err
	}
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
	return r, nil
}

// isUniqueErr matches SQLite's "UNIQUE constraint failed" wrapped
// through database/sql. Same coarse string-match the updaters and
// hostkeys packages use.
func isUniqueErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
