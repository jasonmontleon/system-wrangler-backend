// SPDX-License-Identifier: AGPL-3.0-or-later

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
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

// Unix nanoseconds for timestamps: trivial to sort, no parsing on read,
// round-trips Go's time.Time without precision loss. NULL last_seen = never.
const schema = `
CREATE TABLE IF NOT EXISTS hosts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    status      TEXT NOT NULL,
    last_seen   INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS hosts_created_at ON hosts(created_at, id);
`

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

func (s *SQLiteStore) Get(id string) (System, error) {
	row := s.db.QueryRow(
		`SELECT id, name, hostname, created_at, status, last_seen FROM hosts WHERE id = ?`,
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
		`SELECT id, name, hostname, created_at, status, last_seen FROM hosts ORDER BY created_at, id`,
	)
	if err != nil {
		return nil, fmt.Errorf("systems: list: %w", err)
	}
	defer rows.Close()

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
		status    string
	)
	if err := r.Scan(&h.ID, &h.Name, &h.Hostname, &createdNs, &status, &lastSeen); err != nil {
		return System{}, err
	}
	h.CreatedAt = time.Unix(0, createdNs).UTC()
	h.Status = Status(status)
	if lastSeen.Valid {
		t := time.Unix(0, lastSeen.Int64).UTC()
		h.LastSeen = &t
	}
	return h, nil
}
