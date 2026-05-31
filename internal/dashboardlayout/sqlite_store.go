// SPDX-License-Identifier: Apache-2.0

package dashboardlayout

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SQLiteStore persists user_dashboard_layouts rows. The layout column
// holds the raw JSON string the frontend wrote — the server enforces
// well-formed JSON at the handler boundary, not in SQL.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore migrates the schema and returns a ready store. The
// CREATE is idempotent so subsequent boots are no-ops.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("dashboardlayout: schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS user_dashboard_layouts (
    user_id    TEXT PRIMARY KEY,
    layout     TEXT NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
`

// Get satisfies Store.Get.
func (s *SQLiteStore) Get(userID string) (string, error) {
	var v string
	err := s.db.QueryRow(
		`SELECT layout FROM user_dashboard_layouts WHERE user_id = ?`,
		userID,
	).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("dashboardlayout: get: %w", err)
	}
	return v, nil
}

// Set satisfies Store.Set with INSERT...ON CONFLICT so the call is
// idempotent. updated_at is stamped server-side rather than supplied
// by the caller so client clock skew can't poison the row.
func (s *SQLiteStore) Set(userID, layoutJSON string) error {
	if userID == "" {
		return fmt.Errorf("dashboardlayout: set: user_id required")
	}
	_, err := s.db.Exec(
		`INSERT INTO user_dashboard_layouts (user_id, layout, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT (user_id) DO UPDATE SET
		     layout = excluded.layout,
		     updated_at = excluded.updated_at`,
		userID, layoutJSON, time.Now().UnixMilli(),
	)
	if err != nil {
		return fmt.Errorf("dashboardlayout: set: %w", err)
	}
	return nil
}

// DeleteByUserTx satisfies Store.DeleteByUserTx; wired into the
// auth user-delete transaction so a deleted user's layout cleans up.
func (s *SQLiteStore) DeleteByUserTx(tx *sql.Tx, userID string) error {
	if _, err := tx.Exec(
		`DELETE FROM user_dashboard_layouts WHERE user_id = ?`,
		userID,
	); err != nil {
		return fmt.Errorf("dashboardlayout: delete: %w", err)
	}
	return nil
}
