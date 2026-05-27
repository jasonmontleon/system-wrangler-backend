// SPDX-License-Identifier: Apache-2.0

package labels

import (
	"database/sql"
	"fmt"
	"sync"
)

// StyleStore is the persistence boundary for label color overrides.
// All() returns the whole map in one round-trip — the SPA loads it
// once on mount and updates over SSE, so the chatty path is "get
// everything" rather than per-key.
type StyleStore interface {
	All() (map[string]string, error)
	Set(key, color string) error
	Delete(key string) error
}

// SQLiteStyleStore persists label styles to SQLite. Table is owned by
// this package; the schema is migrated on first NewSQLiteStyleStore.
type SQLiteStyleStore struct {
	db *sql.DB
}

const styleSchema = `
CREATE TABLE IF NOT EXISTS label_styles (
    key    TEXT PRIMARY KEY,
    color  TEXT NOT NULL
) STRICT;
`

// NewSQLiteStyleStore migrates the schema and returns a StyleStore.
// Idempotent.
func NewSQLiteStyleStore(db *sql.DB) (*SQLiteStyleStore, error) {
	if _, err := db.Exec(styleSchema); err != nil {
		return nil, fmt.Errorf("labels: style schema: %w", err)
	}
	return &SQLiteStyleStore{db: db}, nil
}

// All returns every override keyed by label key.
func (s *SQLiteStyleStore) All() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, color FROM label_styles ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("labels: query styles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var key, color string
		if err := rows.Scan(&key, &color); err != nil {
			return nil, fmt.Errorf("labels: scan style: %w", err)
		}
		out[key] = color
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("labels: rows iter styles: %w", err)
	}
	return out, nil
}

// Set upserts a (key, color) override. Validation lives upstream so
// the store can be called by internal code with already-clean values;
// the handler validates the request body before reaching here.
func (s *SQLiteStyleStore) Set(key, color string) error {
	_, err := s.db.Exec(
		`INSERT INTO label_styles (key, color) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET color = excluded.color`,
		key, color,
	)
	if err != nil {
		return fmt.Errorf("labels: style upsert: %w", err)
	}
	return nil
}

// Delete removes the override for a key. Returns ErrNotFound if no row
// exists so the handler can distinguish "already gone" from "deleted".
func (s *SQLiteStyleStore) Delete(key string) error {
	res, err := s.db.Exec(`DELETE FROM label_styles WHERE key = ?`, key)
	if err != nil {
		return fmt.Errorf("labels: style delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("labels: style rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

var _ StyleStore = (*SQLiteStyleStore)(nil)

// MemStyleStore is the in-memory StyleStore used by handler tests.
// Goroutine-safe.
type MemStyleStore struct {
	mu sync.RWMutex
	m  map[string]string
}

// NewMemStyleStore returns an empty in-memory store.
func NewMemStyleStore() *MemStyleStore { return &MemStyleStore{m: map[string]string{}} }

// All returns a copy of the override map.
func (s *MemStyleStore) All() (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out, nil
}

// Set upserts (key, color).
func (s *MemStyleStore) Set(key, color string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = color
	return nil
}

// Delete removes a key. Returns ErrNotFound if it wasn't there.
func (s *MemStyleStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[key]; !ok {
		return ErrNotFound
	}
	delete(s.m, key)
	return nil
}

var _ StyleStore = (*MemStyleStore)(nil)
