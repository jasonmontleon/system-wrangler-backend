// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Store is the persistence boundary for role assignments. Handlers
// and middleware depend on this interface; tests use stubs or the
// in-memory MemStore.
type Store interface {
	// Resolve returns every assignment held by userID. An empty slice
	// is a valid result and means "no permissions" — the caller
	// builds a zero-permission Scope from it.
	Resolve(userID string) ([]Assignment, error)
	// Grant inserts a single assignment. Returns ErrDuplicate if the
	// same (user, group, role) tuple already exists.
	Grant(a Assignment) error
	// Revoke removes a single assignment. Returns ErrNotFound when no
	// matching row exists.
	Revoke(a Assignment) error
	// ListByGroup returns every assignment whose GroupID equals
	// groupID (the global-scope rows are NOT included). Ordered by
	// user_id, role ASC for deterministic UI rendering.
	ListByGroup(groupID string) ([]Assignment, error)
	// ListAll returns every assignment in the table, including global
	// (GroupID == nil) rows. Used by the global admin "all
	// assignments" view.
	ListAll() ([]Assignment, error)
}

// SQLiteStore persists role assignments to SQLite. It owns the
// user_roles table and a small rbac_meta key/value table used to
// gate the one-time "every existing user → global Admin" backfill.
type SQLiteStore struct {
	db *sql.DB
}

// schema creates the user_roles join table plus an expression-based
// UNIQUE index so a NULL group_id (the "global scope" sentinel) is
// deduplicated like any other value. SQLite treats two NULLs as
// distinct in a vanilla UNIQUE constraint, which would let
// (alice, NULL, 'admin') be inserted twice — COALESCE(group_id, ”)
// folds NULL to a fixed empty string for index purposes only.
const schema = `
CREATE TABLE IF NOT EXISTS user_roles (
    user_id   TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id  TEXT             REFERENCES system_groups(id) ON DELETE CASCADE,
    role      TEXT    NOT NULL
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS user_roles_unique
    ON user_roles(user_id, COALESCE(group_id, ''), role);

CREATE INDEX IF NOT EXISTS user_roles_user_id  ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS user_roles_group_id ON user_roles(group_id);

CREATE TABLE IF NOT EXISTS rbac_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
`

// metaBackfilled is the rbac_meta key that records that the one-time
// "every existing user becomes a global Admin" backfill has already
// run. Once set, subsequent boots leave assignments alone — even if
// the user later revokes every role from themselves, restarting the
// container won't silently re-grant Admin.
const metaBackfilled = "v1_backfilled"

// NewSQLiteStore runs the schema migration on db and returns a Store.
// First-boot semantics:
//
//   - If user_roles is empty AND any users exist AND we have never run
//     the backfill before, insert (user_id, NULL, 'admin') for every
//     existing user. This preserves the v1 "every user is admin" floor
//     on upgrade; per research/rbac.md, new installs reach this same
//     point because the setup user is created before NewSQLiteStore
//     runs.
//   - The backfill condition is gated by an rbac_meta sentinel row so a
//     deliberate "demote every admin" can't be undone by a restart.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("rbac: schema: %w", err)
	}
	s := &SQLiteStore{db: db}
	if err := s.backfillOnce(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) backfillOnce() error {
	var marker string
	switch err := s.db.QueryRow(`SELECT value FROM rbac_meta WHERE key = ?`, metaBackfilled).Scan(&marker); {
	case errors.Is(err, sql.ErrNoRows):
		// First time we've seen this DB — fall through and backfill.
	case err != nil:
		return fmt.Errorf("rbac: check backfill marker: %w", err)
	default:
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("rbac: backfill begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.Query(`SELECT id FROM users`)
	if err != nil {
		return fmt.Errorf("rbac: backfill users: %w", err)
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return fmt.Errorf("rbac: backfill scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("rbac: backfill rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("rbac: backfill close: %w", err)
	}
	for _, id := range ids {
		if _, err := tx.Exec(
			`INSERT INTO user_roles (user_id, group_id, role) VALUES (?, NULL, ?)
			 ON CONFLICT DO NOTHING`,
			id, string(RoleAdmin),
		); err != nil {
			return fmt.Errorf("rbac: backfill insert %s: %w", id, err)
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO rbac_meta (key, value) VALUES (?, '1')`,
		metaBackfilled,
	); err != nil {
		return fmt.Errorf("rbac: backfill mark: %w", err)
	}
	return tx.Commit()
}

// Resolve returns every assignment for userID. The returned slice is
// in arbitrary order; callers should not depend on row order. An
// empty slice plus a nil error means "user has no roles" — that is a
// valid state for newly-created users post-RBAC.
func (s *SQLiteStore) Resolve(userID string) ([]Assignment, error) {
	rows, err := s.db.Query(
		`SELECT user_id, group_id, role FROM user_roles WHERE user_id = ?`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("rbac: resolve: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Assignment{}
	for rows.Next() {
		a, err := scanAssignment(rows)
		if err != nil {
			return nil, fmt.Errorf("rbac: resolve scan: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rbac: resolve rows: %w", err)
	}
	return out, nil
}

// Grant inserts a single role assignment. Returns ErrDuplicate when
// the (user_id, group_id, role) tuple already exists, ErrInvalid for
// an unknown role string. FK violations bubble up as a plain error so
// the handler can decide how to render them (404 vs 500).
func (s *SQLiteStore) Grant(a Assignment) error {
	if !a.Role.IsValid() {
		return fmt.Errorf("%w: unknown role %q", ErrInvalid, a.Role)
	}
	if a.UserID == "" {
		return fmt.Errorf("%w: user_id required", ErrInvalid)
	}
	var (
		err error
	)
	if a.GroupID == nil {
		_, err = s.db.Exec(
			`INSERT INTO user_roles (user_id, group_id, role) VALUES (?, NULL, ?)`,
			a.UserID, string(a.Role),
		)
	} else {
		_, err = s.db.Exec(
			`INSERT INTO user_roles (user_id, group_id, role) VALUES (?, ?, ?)`,
			a.UserID, *a.GroupID, string(a.Role),
		)
	}
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return fmt.Errorf("rbac: grant: %w", err)
	}
	return nil
}

// Revoke deletes a single role assignment. Returns ErrNotFound when
// no matching row exists. NULL vs non-NULL group_id is matched
// exactly: nil GroupID only revokes the global row.
func (s *SQLiteStore) Revoke(a Assignment) error {
	if !a.Role.IsValid() {
		return fmt.Errorf("%w: unknown role %q", ErrInvalid, a.Role)
	}
	var (
		res sql.Result
		err error
	)
	if a.GroupID == nil {
		res, err = s.db.Exec(
			`DELETE FROM user_roles WHERE user_id = ? AND group_id IS NULL AND role = ?`,
			a.UserID, string(a.Role),
		)
	} else {
		res, err = s.db.Exec(
			`DELETE FROM user_roles WHERE user_id = ? AND group_id = ? AND role = ?`,
			a.UserID, *a.GroupID, string(a.Role),
		)
	}
	if err != nil {
		return fmt.Errorf("rbac: revoke: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rbac: revoke rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListByGroup returns every per-group assignment for the supplied
// group ID. Global (NULL) rows are excluded — this is the
// "who has access to THIS group" projection used by Group Detail.
func (s *SQLiteStore) ListByGroup(groupID string) ([]Assignment, error) {
	rows, err := s.db.Query(
		`SELECT user_id, group_id, role FROM user_roles
		 WHERE group_id = ?
		 ORDER BY user_id, role`,
		groupID,
	)
	if err != nil {
		return nil, fmt.Errorf("rbac: list by group: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Assignment{}
	for rows.Next() {
		a, err := scanAssignment(rows)
		if err != nil {
			return nil, fmt.Errorf("rbac: list by group scan: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rbac: list by group rows: %w", err)
	}
	return out, nil
}

// ListAll returns every assignment in the table including global
// (NULL group_id) rows. The admin "everything" projection.
func (s *SQLiteStore) ListAll() ([]Assignment, error) {
	rows, err := s.db.Query(
		`SELECT user_id, group_id, role FROM user_roles
		 ORDER BY user_id, group_id, role`,
	)
	if err != nil {
		return nil, fmt.Errorf("rbac: list all: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Assignment{}
	for rows.Next() {
		a, err := scanAssignment(rows)
		if err != nil {
			return nil, fmt.Errorf("rbac: list all scan: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rbac: list all rows: %w", err)
	}
	return out, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAssignment(r rowScanner) (Assignment, error) {
	var (
		a       Assignment
		groupID sql.NullString
		role    string
	)
	if err := r.Scan(&a.UserID, &groupID, &role); err != nil {
		return Assignment{}, err
	}
	if groupID.Valid {
		gid := groupID.String
		a.GroupID = &gid
	}
	a.Role = Role(role)
	return a, nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
