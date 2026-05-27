// SPDX-License-Identifier: Apache-2.0

package holds

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SQLiteStore is the SQLite-backed Store. The *sql.DB is caller-owned;
// this package only owns its own table. Schema migration runs on
// NewSQLiteStore and is a no-op on already-initialized databases.
type SQLiteStore struct {
	db *sql.DB

	Now func() time.Time
}

// NewSQLiteStore migrates the schema and returns a Store.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("holds: schema: %w", err)
	}
	return &SQLiteStore{db: db, Now: time.Now}, nil
}

// schema declares the managed_holds table. The (system_id, updater,
// pattern) composite PK enforces uniqueness without a separate index.
// STRICT typing matches the rest of the codebase.
const schema = `
CREATE TABLE IF NOT EXISTS managed_holds (
    system_id  TEXT NOT NULL,
    updater    TEXT NOT NULL,
    pattern    TEXT NOT NULL,
    set_at     INTEGER NOT NULL,
    PRIMARY KEY (system_id, updater, pattern)
) STRICT;

CREATE INDEX IF NOT EXISTS managed_holds_system_updater
    ON managed_holds(system_id, updater);
`

// List returns the patterns SW manages on (systemID, updaterID).
func (s *SQLiteStore) List(systemID, updaterID string) ([]string, error) {
	if strings.TrimSpace(systemID) == "" || strings.TrimSpace(updaterID) == "" {
		return nil, fmt.Errorf("%w: system_id and updater required", ErrInvalid)
	}
	rows, err := s.db.Query(
		`SELECT pattern FROM managed_holds
		 WHERE system_id = ? AND updater = ?
		 ORDER BY pattern`,
		systemID, updaterID,
	)
	if err != nil {
		return nil, fmt.Errorf("holds: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("holds: list scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("holds: list rows: %w", err)
	}
	return out, nil
}

// Replace sets the managed pattern set for (systemID, updaterID) to
// exactly desired. The transaction is small (one DELETE + N INSERTs)
// and the table is single-pair-scoped so we don't worry about lock
// contention. Empty desired clears the pair entirely.
func (s *SQLiteStore) Replace(systemID, updaterID string, desired []string) error {
	if strings.TrimSpace(systemID) == "" || strings.TrimSpace(updaterID) == "" {
		return fmt.Errorf("%w: system_id and updater required", ErrInvalid)
	}
	// Stable, deduplicated input — protects against caller mistakes.
	dedup := dedupSort(desired)
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("holds: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(
		`DELETE FROM managed_holds WHERE system_id = ? AND updater = ?`,
		systemID, updaterID,
	); err != nil {
		return fmt.Errorf("holds: clear: %w", err)
	}
	now := s.now().UnixNano()
	for _, p := range dedup {
		if _, err := tx.Exec(
			`INSERT INTO managed_holds (system_id, updater, pattern, set_at)
			 VALUES (?, ?, ?, ?)`,
			systemID, updaterID, p, now,
		); err != nil {
			return fmt.Errorf("holds: insert: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("holds: commit: %w", err)
	}
	return nil
}

// RemoveSystem clears every hold row for the system.
func (s *SQLiteStore) RemoveSystem(systemID string) (int, error) {
	if strings.TrimSpace(systemID) == "" {
		return 0, fmt.Errorf("%w: system_id required", ErrInvalid)
	}
	res, err := s.db.Exec(`DELETE FROM managed_holds WHERE system_id = ?`, systemID)
	if err != nil {
		return 0, fmt.Errorf("holds: remove system: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("holds: rows affected: %w", err)
	}
	return int(n), nil
}

func (s *SQLiteStore) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

func dedupSort(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
