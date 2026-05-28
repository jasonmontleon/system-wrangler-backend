// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SQLiteStore is a Store backed by SQLite. The *sql.DB is owned by the caller
// (typically opened via internal/database.Open); this lets every domain
// package share one connection pool without one of them owning the others'
// tables.
type SQLiteStore struct {
	db *sql.DB

	NewID func() string
	Now   func() time.Time
}

// NewSQLiteStore ensures the systems table exist on db and returns a Store
// using them. Calling it on an already-initialized db is a no-op (CREATE
// TABLE IF NOT EXISTS).
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("systems: schema: %w", err)
	}
	if err := addGroupIDColumn(db); err != nil {
		return nil, fmt.Errorf("systems: migrate group_id: %w", err)
	}
	if err := addIsWindowsColumn(db); err != nil {
		return nil, fmt.Errorf("systems: migrate is_windows: %w", err)
	}
	if err := addPlatformInfoColumns(db); err != nil {
		return nil, fmt.Errorf("systems: migrate platform info: %w", err)
	}
	if err := addRebootRequiredColumn(db); err != nil {
		return nil, fmt.Errorf("systems: migrate reboot_required_at: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

// Unix nanoseconds for timestamps: trivial to sort, no parsing on read,
// round-trips Go's time.Time without precision loss. NULL last_seen = never.
// group_id is a nullable text column joined client-side against
// /api/groups; this package deliberately does not import groups so the
// dependency arrow only points the other way. The hosts_group_id index is
// not in this schema because it would fail on databases predating the
// group_id column — addGroupIDColumn creates it after the migration.
const schema = `
CREATE TABLE IF NOT EXISTS hosts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    status      TEXT NOT NULL,
    last_seen   INTEGER,
    group_id    TEXT,
    is_windows  INTEGER NOT NULL DEFAULT 0,
    os_family       TEXT NOT NULL DEFAULT '',
    os_distribution TEXT NOT NULL DEFAULT '',
    virtualization  TEXT NOT NULL DEFAULT '',
    reboot_required_at INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS hosts_created_at ON hosts(created_at, id);
`

// addGroupIDColumn brings older databases (created before the group_id
// column existed) up to schema, then ensures the supporting index exists.
// SQLite has no "ADD COLUMN IF NOT EXISTS", so the pragma check is the
// portable way. The index step runs unconditionally because a fresh
// install's CREATE TABLE already produced the column.
func addGroupIDColumn(db *sql.DB) error {
	row := db.QueryRow(`SELECT 1 FROM pragma_table_info('hosts') WHERE name = 'group_id'`)
	var found int
	switch err := row.Scan(&found); {
	case err == nil:
		// column already present — nothing to ALTER
	case errors.Is(err, sql.ErrNoRows):
		if _, err := db.Exec(`ALTER TABLE hosts ADD COLUMN group_id TEXT`); err != nil {
			return err
		}
	default:
		return err
	}
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS hosts_group_id ON hosts(group_id)`)
	return err
}

// addIsWindowsColumn brings older databases up to schema, mirroring the
// addGroupIDColumn pattern. The column is the operator-set platform flag
// the inventory writer and Ping module-selector branch on.
func addIsWindowsColumn(db *sql.DB) error {
	row := db.QueryRow(`SELECT 1 FROM pragma_table_info('hosts') WHERE name = 'is_windows'`)
	var found int
	switch err := row.Scan(&found); {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		_, err := db.Exec(`ALTER TABLE hosts ADD COLUMN is_windows INTEGER NOT NULL DEFAULT 0`)
		return err
	default:
		return err
	}
}

// addPlatformInfoColumns adds os_family, os_distribution, and
// virtualization columns to older hosts tables. Each column probes
// independently so a partially-migrated database (rare but possible
// across upgrade interruptions) self-heals on the next start.
func addPlatformInfoColumns(db *sql.DB) error {
	for _, col := range []string{"os_family", "os_distribution", "virtualization"} {
		row := db.QueryRow(`SELECT 1 FROM pragma_table_info('hosts') WHERE name = ?`, col)
		var found int
		switch err := row.Scan(&found); {
		case err == nil:
			continue
		case errors.Is(err, sql.ErrNoRows):
			//nolint:gosec // col is a fixed string literal from the loop above, not user input
			if _, err := db.Exec(`ALTER TABLE hosts ADD COLUMN ` + col + ` TEXT NOT NULL DEFAULT ''`); err != nil {
				return err
			}
		default:
			return err
		}
	}
	return nil
}

// addRebootRequiredColumn brings older databases up to schema. The
// column is nullable: NULL means "no SW-known reboot requirement,"
// non-NULL is the epoch-ns timestamp of the apply run that flipped
// the host into needs-reboot state. Cleared by the next clean
// inspect/check/apply (no marker re-emit).
func addRebootRequiredColumn(db *sql.DB) error {
	row := db.QueryRow(`SELECT 1 FROM pragma_table_info('hosts') WHERE name = 'reboot_required_at'`)
	var found int
	switch err := row.Scan(&found); {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		_, err := db.Exec(`ALTER TABLE hosts ADD COLUMN reboot_required_at INTEGER`)
		return err
	default:
		return err
	}
}

// Create persists a new System after running SystemInput.Validate.
func (s *SQLiteStore) Create(in SystemInput) (System, error) {
	return s.createWith(s.db, in)
}

// CreateTx persists a new System inside the caller's tx so the audit
// row that accompanies the change can commit alongside the row itself.
// A nil tx falls back to the non-transactional path.
func (s *SQLiteStore) CreateTx(tx *sql.Tx, in SystemInput) (System, error) {
	if tx == nil {
		return s.Create(in)
	}
	return s.createWith(tx, in)
}

// execer covers both *sql.DB and *sql.Tx so createWith / deleteWith serve
// both call sites without duplication. Mirrors the same pattern used in
// internal/audit/store.go.
type execer interface {
	Exec(q string, args ...any) (sql.Result, error)
}

func (s *SQLiteStore) createWith(e execer, in SystemInput) (System, error) {
	if err := in.Validate(); err != nil {
		return System{}, err
	}
	h := System{
		ID:        s.NewID(),
		Name:      strings.TrimSpace(in.Name),
		Hostname:  strings.TrimSpace(in.Hostname),
		CreatedAt: s.Now().UTC(),
		Status:    StatusUnprobed,
	}
	_, err := e.Exec(
		`INSERT INTO hosts (id, name, hostname, created_at, status) VALUES (?, ?, ?, ?, ?)`,
		h.ID, h.Name, h.Hostname, h.CreatedAt.UnixNano(), string(h.Status),
	)
	if err != nil {
		return System{}, fmt.Errorf("systems: insert: %w", err)
	}
	return h, nil
}

// Get returns the System with the given ID, or ErrNotFound.
func (s *SQLiteStore) Get(id string) (System, error) {
	row := s.db.QueryRow(
		`SELECT id, name, hostname, created_at, status, last_seen, group_id, is_windows, os_family, os_distribution, virtualization, reboot_required_at FROM hosts WHERE id = ?`,
		id,
	)
	h, err := scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return System{}, ErrNotFound
	}
	return h, err
}

// List returns systems ordered by created_at asc with id as tiebreaker, matching
// MemStore so handler behavior is identical regardless of backend.
func (s *SQLiteStore) List() ([]System, error) {
	rows, err := s.db.Query(
		`SELECT id, name, hostname, created_at, status, last_seen, group_id, is_windows, os_family, os_distribution, virtualization, reboot_required_at FROM hosts ORDER BY created_at, id`,
	)
	if err != nil {
		return nil, fmt.Errorf("systems: list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []System{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("systems: scan: %w", err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("systems: list rows: %w", err)
	}
	return out, nil
}

// Delete removes the System with the given ID, or returns ErrNotFound.
func (s *SQLiteStore) Delete(id string) error {
	return s.deleteWith(s.db, id)
}

// DeleteTx removes the System inside the caller's tx so the audit row can
// commit alongside the row. nil tx falls through to Delete.
func (s *SQLiteStore) DeleteTx(tx *sql.Tx, id string) error {
	if tx == nil {
		return s.Delete(id)
	}
	return s.deleteWith(tx, id)
}

func (s *SQLiteStore) deleteWith(e execer, id string) error {
	res, err := e.Exec(`DELETE FROM hosts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("systems: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetGroup assigns a system to a group, or clears the assignment when
// groupID is nil. Returns ErrNotFound if no row matches systemID.
func (s *SQLiteStore) SetGroup(systemID string, groupID *string) error {
	var (
		res sql.Result
		err error
	)
	if groupID == nil {
		res, err = s.db.Exec(`UPDATE hosts SET group_id = NULL WHERE id = ?`, systemID)
	} else {
		res, err = s.db.Exec(`UPDATE hosts SET group_id = ? WHERE id = ?`, *groupID, systemID)
	}
	if err != nil {
		return fmt.Errorf("systems: set group: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearGroup nils out group_id on every system whose group_id matches
// groupID. Called by the groups store on Delete so that removing a group
// leaves member systems intact but ungrouped (cascade-set-null behavior
// without relying on an SQLite FK).
func (s *SQLiteStore) ClearGroup(groupID string) error {
	_, err := s.db.Exec(`UPDATE hosts SET group_id = NULL WHERE group_id = ?`, groupID)
	if err != nil {
		return fmt.Errorf("systems: clear group: %w", err)
	}
	return nil
}

// UpdateProbe mirrors MemStore: success sets Status + LastSeen; failure sets
// Status only, preserving any prior LastSeen.
func (s *SQLiteStore) UpdateProbe(id string, ok bool, when time.Time) error {
	when = when.UTC()
	var (
		res sql.Result
		err error
	)
	if ok {
		res, err = s.db.Exec(
			`UPDATE hosts SET status = ?, last_seen = ? WHERE id = ?`,
			string(StatusReachable), when.UnixNano(), id,
		)
	} else {
		res, err = s.db.Exec(
			`UPDATE hosts SET status = ? WHERE id = ?`,
			string(StatusUnreachable), id,
		)
	}
	if err != nil {
		return fmt.Errorf("systems: update probe: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// rowScanner unifies *sql.Row and *sql.Rows so scanHost serves Get and List.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanHost(r rowScanner) (System, error) {
	var (
		h          System
		createdNs  int64
		lastSeen   sql.NullInt64
		groupID    sql.NullString
		status     string
		isWindows  int64
		rebootAtNs sql.NullInt64
	)
	if err := r.Scan(
		&h.ID, &h.Name, &h.Hostname, &createdNs, &status, &lastSeen,
		&groupID, &isWindows,
		&h.OSFamily, &h.OSDistribution, &h.Virtualization,
		&rebootAtNs,
	); err != nil {
		return System{}, err
	}
	h.CreatedAt = time.Unix(0, createdNs).UTC()
	h.Status = Status(status)
	if lastSeen.Valid {
		t := time.Unix(0, lastSeen.Int64).UTC()
		h.LastSeen = &t
	}
	if groupID.Valid {
		v := groupID.String
		h.GroupID = &v
	}
	h.IsWindows = isWindows != 0
	if rebootAtNs.Valid {
		t := time.Unix(0, rebootAtNs.Int64).UTC()
		h.RebootRequiredAt = &t
	}
	return h, nil
}

// SetPlatform updates the is_windows flag for systemID. Returns
// ErrNotFound if no row matches.
func (s *SQLiteStore) SetPlatform(systemID string, isWindows bool) error {
	return s.setPlatformWith(s.db, systemID, isWindows)
}

// SetPlatformTx mirrors SetPlatform inside the caller's tx so the
// mutation and its audit row commit together. nil tx falls back.
func (s *SQLiteStore) SetPlatformTx(tx *sql.Tx, systemID string, isWindows bool) error {
	if tx == nil {
		return s.SetPlatform(systemID, isWindows)
	}
	return s.setPlatformWith(tx, systemID, isWindows)
}

func (s *SQLiteStore) setPlatformWith(e execer, systemID string, isWindows bool) error {
	res, err := e.Exec(`UPDATE hosts SET is_windows = ? WHERE id = ?`, boolToInt(isWindows), systemID)
	if err != nil {
		return fmt.Errorf("systems: set platform: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SetRebootRequired stamps reboot_required_at on the host so the SPA
// can show a "reboot required" chip immediately after an apply
// emitted the SW_REBOOT_REQUIRED marker, without waiting for the
// next exporter scrape to land. Subsequent calls overwrite the
// timestamp so the most recent triggering apply is the one
// displayed.
func (s *SQLiteStore) SetRebootRequired(systemID string, at time.Time) error {
	res, err := s.db.Exec(`UPDATE hosts SET reboot_required_at = ? WHERE id = ?`, at.UTC().UnixNano(), systemID)
	if err != nil {
		return fmt.Errorf("systems: set reboot required: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearRebootRequired nils reboot_required_at. Called when a
// successful run completes without re-emitting the marker (the
// natural "reboot happened and Check confirms no pending reboot"
// path).
func (s *SQLiteStore) ClearRebootRequired(systemID string) error {
	res, err := s.db.Exec(`UPDATE hosts SET reboot_required_at = NULL WHERE id = ?`, systemID)
	if err != nil {
		return fmt.Errorf("systems: clear reboot required: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPlatformInfo persists the detected OS family, distribution, and
// virtualization fields the inspect playbook surfaced via the
// SW_OS_* / SW_VIRTUALIZATION markers. Returns ErrNotFound when no
// host matches. Empty strings are valid — they represent "not yet
// detected" / "bare metal" respectively, and overwriting with empty
// is the intentional path when a host's inspect can no longer reach
// the gather_facts task.
func (s *SQLiteStore) SetPlatformInfo(systemID, osFamily, osDistribution, virtualization string) error {
	res, err := s.db.Exec(
		`UPDATE hosts SET os_family = ?, os_distribution = ?, virtualization = ? WHERE id = ?`,
		osFamily, osDistribution, virtualization, systemID,
	)
	if err != nil {
		return fmt.Errorf("systems: set platform info: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
