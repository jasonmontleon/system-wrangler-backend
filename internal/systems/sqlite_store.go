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
    group_id    TEXT
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

// Create persists a new System after running SystemInput.Validate.
func (s *SQLiteStore) Create(in SystemInput) (System, error) {
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
	_, err := s.db.Exec(
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
		`SELECT id, name, hostname, created_at, status, last_seen, group_id FROM hosts WHERE id = ?`,
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
		`SELECT id, name, hostname, created_at, status, last_seen, group_id FROM hosts ORDER BY created_at, id`,
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
	res, err := s.db.Exec(`DELETE FROM hosts WHERE id = ?`, id)
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
		h         System
		createdNs int64
		lastSeen  sql.NullInt64
		groupID   sql.NullString
		status    string
	)
	if err := r.Scan(&h.ID, &h.Name, &h.Hostname, &createdNs, &status, &lastSeen, &groupID); err != nil {
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
	return h, nil
}
