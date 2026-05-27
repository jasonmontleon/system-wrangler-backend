// SPDX-License-Identifier: Apache-2.0

package labels

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// SQLiteStore persists labels in SQLite. The system_labels table FK
// references hosts(id) ON DELETE CASCADE so deleting a system also
// removes its labels in a single statement.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore migrates the schema and returns a Store. Idempotent;
// calling it on a db that already has the table is a no-op.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("labels: schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS system_labels (
    system_id  TEXT    NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    key        TEXT    NOT NULL,
    value      TEXT,
    PRIMARY KEY (system_id, key)
) STRICT;

CREATE INDEX IF NOT EXISTS system_labels_kv ON system_labels(key, value);
`

// Set inserts or updates a label. We do an explicit UPSERT so a Set on
// an existing (system_id, key) overwrites rather than erroring on the PK.
func (s *SQLiteStore) Set(systemID, key string, value *string, allowReserved bool) (Label, error) {
	if systemID == "" {
		return Label{}, fmt.Errorf("%w: system_id is required", ErrInvalid)
	}
	if err := ValidateKey(key, allowReserved); err != nil {
		return Label{}, err
	}
	if err := ValidateValue(value); err != nil {
		return Label{}, err
	}
	_, err := s.db.Exec(
		`INSERT INTO system_labels (system_id, key, value) VALUES (?, ?, ?)
		 ON CONFLICT(system_id, key) DO UPDATE SET value = excluded.value`,
		systemID, key, value,
	)
	if err != nil {
		if isFKViolation(err) {
			return Label{}, fmt.Errorf("%w: system %s", ErrNotFound, systemID)
		}
		return Label{}, fmt.Errorf("labels: upsert: %w", err)
	}
	return Label{Key: key, Value: value}, nil
}

// Delete removes a label. Returns ErrNotFound when no matching row
// exists so the handler can distinguish "already gone" from "deleted".
func (s *SQLiteStore) Delete(systemID, key string) error {
	res, err := s.db.Exec(
		`DELETE FROM system_labels WHERE system_id = ? AND key = ?`,
		systemID, key,
	)
	if err != nil {
		return fmt.Errorf("labels: delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("labels: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ForSystem returns every label on systemID, sorted by key.
func (s *SQLiteStore) ForSystem(systemID string) ([]Label, error) {
	rows, err := s.db.Query(
		`SELECT key, value FROM system_labels WHERE system_id = ? ORDER BY key`,
		systemID,
	)
	if err != nil {
		return nil, fmt.Errorf("labels: query for system: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]Label, 0)
	for rows.Next() {
		var l Label
		var v sql.NullString
		if err := rows.Scan(&l.Key, &v); err != nil {
			return nil, fmt.Errorf("labels: scan: %w", err)
		}
		if v.Valid {
			s := v.String
			l.Value = &s
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("labels: rows iter: %w", err)
	}
	return out, nil
}

// ForSystems bulk-loads labels for the given system IDs in one query.
// Empty input returns an empty map without hitting the database.
func (s *SQLiteStore) ForSystems(systemIDs []string) (map[string][]Label, error) {
	out := make(map[string][]Label, len(systemIDs))
	if len(systemIDs) == 0 {
		return out, nil
	}
	placeholders := strings.Repeat("?,", len(systemIDs))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(systemIDs))
	for i, id := range systemIDs {
		args[i] = id
	}
	// Placeholders are a fixed run of "?" markers derived from input
	// length; nothing user-supplied reaches the SQL string. gosec G202
	// can't see that statically.
	q := "SELECT system_id, key, value FROM system_labels WHERE system_id IN (" + placeholders + ") ORDER BY system_id, key" //nolint:gosec
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("labels: query bulk: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var sid, key string
		var v sql.NullString
		if err := rows.Scan(&sid, &key, &v); err != nil {
			return nil, fmt.Errorf("labels: scan bulk: %w", err)
		}
		l := Label{Key: key}
		if v.Valid {
			s := v.String
			l.Value = &s
		}
		out[sid] = append(out[sid], l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("labels: rows iter bulk: %w", err)
	}
	return out, nil
}

// Summary returns distinct keys with per-value cardinalities. Bare tags
// (NULL value rows) collapse into one ValueSummary with Value == nil.
func (s *SQLiteStore) Summary() ([]KeySummary, error) {
	rows, err := s.db.Query(
		`SELECT key, value, COUNT(*)
		 FROM system_labels
		 GROUP BY key, value
		 ORDER BY key, value`,
	)
	if err != nil {
		return nil, fmt.Errorf("labels: summary: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byKey := map[string]*KeySummary{}
	for rows.Next() {
		var key string
		var val sql.NullString
		var count int
		if err := rows.Scan(&key, &val, &count); err != nil {
			return nil, fmt.Errorf("labels: scan summary: %w", err)
		}
		ks, ok := byKey[key]
		if !ok {
			ks = &KeySummary{Key: key}
			byKey[key] = ks
		}
		vs := ValueSummary{Count: count}
		if val.Valid {
			s := val.String
			vs.Value = &s
		}
		ks.Values = append(ks.Values, vs)
		ks.Count += count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("labels: rows iter summary: %w", err)
	}
	out := make([]KeySummary, 0, len(byKey))
	for _, ks := range byKey {
		out = append(out, *ks)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// isFKViolation matches modernc.org/sqlite's foreign key error so the
// store can surface "system does not exist" as ErrNotFound rather than
// a generic backend error.
func isFKViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "FOREIGN KEY constraint failed") ||
		strings.Contains(msg, "foreign key constraint")
}

var _ Store = (*SQLiteStore)(nil)
