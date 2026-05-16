// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"database/sql"
	"errors"
	"fmt"
)

// SQLiteStore persists key/value pairs in a single table. The
// schema is intentionally minimal so future scalar settings can
// land without migration; structured settings should grow their
// own package rather than abuse the value column.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore migrates the schema and returns a ready store.
// Idempotent across boots.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("settings: schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS system_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
`

// Get satisfies Store.Get. ErrNotFound is returned when the key
// has never been set; callers translate that to a default.
func (s *SQLiteStore) Get(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM system_settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("settings: get: %w", err)
	}
	return v, nil
}

// Set satisfies Store.Set with INSERT...ON CONFLICT so the call is
// idempotent — the same shape every other store in the tree uses.
func (s *SQLiteStore) Set(key, value string) error {
	if key == "" {
		return fmt.Errorf("%w: key required", ErrInvalid)
	}
	_, err := s.db.Exec(
		`INSERT INTO system_settings (key, value) VALUES (?, ?)
		 ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("settings: set: %w", err)
	}
	return nil
}

// All satisfies Store.All. The map is keyed by setting name; values
// are the raw strings the operator stored. Empty map when the table
// has no rows.
func (s *SQLiteStore) All() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM system_settings`)
	if err != nil {
		return nil, fmt.Errorf("settings: all: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("settings: scan: %w", err)
		}
		out[k] = v
	}
	return out, rows.Err()
}
