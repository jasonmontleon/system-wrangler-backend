// SPDX-License-Identifier: Apache-2.0

package groups

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SQLiteStore persists groups to SQLite. It owns the system_groups table.
// The hosts.group_id column belongs to the systems package; on Delete the
// store nils out matching hosts.group_id in the same transaction so the
// cascade behaves like ON DELETE SET NULL without an SQLite FK.
type SQLiteStore struct {
	db *sql.DB

	NewID func() string
	Now   func() time.Time
}

// NewSQLiteStore migrates the schema and returns a Store. Calling it on an
// already-initialized db is a no-op.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("groups: schema: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS system_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS system_groups_created_at ON system_groups(created_at, id);
`

// Create inserts a new group. Returns ErrDuplicate if the name (after
// trimming) collides with an existing row.
func (s *SQLiteStore) Create(in GroupInput) (Group, error) {
	if err := in.Validate(); err != nil {
		return Group{}, err
	}
	g := Group{
		ID:        s.NewID(),
		Name:      strings.TrimSpace(in.Name),
		CreatedAt: s.Now().UTC(),
	}
	_, err := s.db.Exec(
		`INSERT INTO system_groups (id, name, created_at) VALUES (?, ?, ?)`,
		g.ID, g.Name, g.CreatedAt.UnixNano(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Group{}, fmt.Errorf("%w: %s", ErrDuplicate, g.Name)
		}
		return Group{}, fmt.Errorf("groups: insert: %w", err)
	}
	return g, nil
}

// Get returns the group with the given id (including system count).
func (s *SQLiteStore) Get(id string) (Group, error) {
	row := s.db.QueryRow(
		`SELECT g.id, g.name, g.created_at,
		        (SELECT COUNT(*) FROM hosts h WHERE h.group_id = g.id)
		 FROM system_groups g
		 WHERE g.id = ?`,
		id,
	)
	g, err := scanGroup(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	return g, err
}

// List returns all groups ordered by created_at asc, id as tiebreaker.
func (s *SQLiteStore) List() ([]Group, error) {
	rows, err := s.db.Query(
		`SELECT g.id, g.name, g.created_at,
		        (SELECT COUNT(*) FROM hosts h WHERE h.group_id = g.id)
		 FROM system_groups g
		 ORDER BY g.created_at, g.id`,
	)
	if err != nil {
		return nil, fmt.Errorf("groups: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, fmt.Errorf("groups: scan: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("groups: list rows: %w", err)
	}
	return out, nil
}

// Rename updates the name of an existing group. Returns ErrDuplicate if
// another group already holds the new name.
func (s *SQLiteStore) Rename(id string, in GroupInput) (Group, error) {
	if err := in.Validate(); err != nil {
		return Group{}, err
	}
	name := strings.TrimSpace(in.Name)
	res, err := s.db.Exec(
		`UPDATE system_groups SET name = ? WHERE id = ?`,
		name, id,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Group{}, fmt.Errorf("%w: %s", ErrDuplicate, name)
		}
		return Group{}, fmt.Errorf("groups: rename: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Group{}, ErrNotFound
	}
	return s.Get(id)
}

// Delete removes the group and clears group_id on every system that was
// a member, atomically. Member systems are not removed — only ungrouped.
func (s *SQLiteStore) Delete(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("groups: delete begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`UPDATE hosts SET group_id = NULL WHERE group_id = ?`, id); err != nil {
		return fmt.Errorf("groups: delete clear: %w", err)
	}
	res, err := tx.Exec(`DELETE FROM system_groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("groups: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanGroup(r rowScanner) (Group, error) {
	var (
		g         Group
		createdNs int64
		count     int
	)
	if err := r.Scan(&g.ID, &g.Name, &createdNs, &count); err != nil {
		return Group{}, err
	}
	g.CreatedAt = time.Unix(0, createdNs).UTC()
	g.SystemCount = count
	return g, nil
}

// isUniqueViolation checks for the SQLite UNIQUE constraint error without
// importing the driver package directly. modernc.org/sqlite surfaces the
// message "UNIQUE constraint failed" in Error(); matching on that string
// is the documented portable approach.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
