// SPDX-License-Identifier: Apache-2.0

package exclusions

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SQLiteStore is the SQLite-backed Store. The *sql.DB is owned by the
// caller (typically opened via internal/database.Open); this package
// only owns its own table. Group / system membership joins reference
// hosts (h) and system_groups (g) but never declare them — the
// schemas live in their own packages.
type SQLiteStore struct {
	db *sql.DB

	NewID func() string
	Now   func() time.Time
}

// NewSQLiteStore migrates the schema and returns a Store. Calling it
// on an already-initialized db is a no-op.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("exclusions: schema: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

// schema declares the package_exclusions table. STRICT typing matches
// the rest of the codebase. The CHECK constraints encode the
// (scope, target_id) shape — global rows must carry the empty-string
// sentinel; group / system rows must populate target_id with a real
// id. UNIQUE prevents duplicate rules at the same layer.
//
// Empty-string (not NULL) is used for the global-scope target_id so
// the natural UNIQUE constraint dedupes global rows — SQLite treats
// every NULL as distinct, which would silently allow two identical
// global rules. The Go-side API still keeps the "no enclosing
// resource" semantic intact (the handler refuses non-empty target_id
// on global writes; the Exclusion JSON omits the field).
//
// Cross-package cascade on group / system deletion isn't FK-enforced
// (hosts / system_groups live in other packages and SQLite FKs aren't
// declared here). Orphaned rows are harmless: ResolveForSystem
// joins through hosts.group_id so they never surface; cleanup hooks
// can land later if accumulation becomes a real concern.
const schema = `
CREATE TABLE IF NOT EXISTS package_exclusions (
    id          TEXT PRIMARY KEY,
    scope       TEXT NOT NULL CHECK (scope IN ('global', 'group', 'system')),
    target_id   TEXT NOT NULL DEFAULT '',
    updater     TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    created_by  TEXT NOT NULL,
    CHECK (
        (scope = 'global' AND target_id = '')
        OR (scope IN ('group', 'system') AND target_id <> '')
    ),
    UNIQUE (scope, target_id, updater, pattern)
) STRICT;

CREATE INDEX IF NOT EXISTS package_exclusions_scope ON package_exclusions(scope, target_id);
CREATE INDEX IF NOT EXISTS package_exclusions_updater ON package_exclusions(updater);
`

// Create persists a new exclusion. Caller-side validation already ran;
// this method enforces only the (scope, target) coupling that the
// SQL-side CHECK also catches but with a friendlier error message,
// plus the duplicate translation.
func (s *SQLiteStore) Create(scope Scope, targetID, updater, pattern, reason, createdBy string) (Exclusion, error) {
	if !scope.IsValid() {
		return Exclusion{}, fmt.Errorf("%w: scope %q", ErrInvalid, scope)
	}
	if scope == ScopeGlobal && targetID != "" {
		return Exclusion{}, fmt.Errorf("%w: global scope must not carry target_id", ErrInvalid)
	}
	if scope != ScopeGlobal && targetID == "" {
		return Exclusion{}, fmt.Errorf("%w: %s scope requires target_id", ErrInvalid, scope)
	}
	if strings.TrimSpace(createdBy) == "" {
		return Exclusion{}, fmt.Errorf("%w: created_by required", ErrInvalid)
	}

	row := Exclusion{
		ID:        s.NewID(),
		Scope:     scope,
		TargetID:  targetID,
		Updater:   strings.TrimSpace(updater),
		Pattern:   strings.TrimSpace(pattern),
		Reason:    strings.TrimSpace(reason),
		CreatedAt: s.Now().UTC(),
		CreatedBy: createdBy,
	}
	_, err := s.db.Exec(
		`INSERT INTO package_exclusions
		 (id, scope, target_id, updater, pattern, reason, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		row.ID, string(row.Scope), row.TargetID, row.Updater, row.Pattern, row.Reason,
		row.CreatedAt.UnixNano(), row.CreatedBy,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Exclusion{}, fmt.Errorf("%w: %s/%s/%s", ErrDuplicate, row.Updater, row.Pattern, scope)
		}
		return Exclusion{}, fmt.Errorf("exclusions: insert: %w", err)
	}
	return row, nil
}

// Get loads a row by id.
func (s *SQLiteStore) Get(id string) (Exclusion, error) {
	row := s.db.QueryRow(
		`SELECT id, scope, target_id, updater, pattern, reason, created_at, created_by
		 FROM package_exclusions WHERE id = ?`, id)
	e, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Exclusion{}, ErrNotFound
	}
	return e, err
}

// Delete removes a row. ErrNotFound when the id doesn't match.
func (s *SQLiteStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM package_exclusions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("exclusions: delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("exclusions: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListGlobal returns ScopeGlobal rows, oldest first.
func (s *SQLiteStore) ListGlobal() ([]Exclusion, error) {
	return s.list(`WHERE scope = 'global'`)
}

// ListGroup returns ScopeGroup rows for the named group, oldest first.
func (s *SQLiteStore) ListGroup(groupID string) ([]Exclusion, error) {
	return s.list(`WHERE scope = 'group' AND target_id = ?`, groupID)
}

// ListSystem returns ScopeSystem rows for the named system, oldest first.
func (s *SQLiteStore) ListSystem(systemID string) ([]Exclusion, error) {
	return s.list(`WHERE scope = 'system' AND target_id = ?`, systemID)
}

func (s *SQLiteStore) list(where string, args ...any) ([]Exclusion, error) {
	// where contains only fixed string literals declared in this file;
	// args carry the bind values that reach SQL.
	//nolint:gosec // safe — where is a const-string composed from package-internal templates
	rows, err := s.db.Query(
		`SELECT id, scope, target_id, updater, pattern, reason, created_at, created_by
		 FROM package_exclusions `+where+` ORDER BY created_at, id`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("exclusions: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Exclusion{}
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("exclusions: scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("exclusions: rows: %w", err)
	}
	return out, nil
}

// ResolveForSystem returns the deduplicated patterns that apply for
// (systemID, updaterID). Union spans:
//   - Global rows where updater = updaterID OR updater = '*'.
//   - Group rows where the system's group matches AND the updater
//     clause matches.
//   - System rows for this system AND the updater clause matches.
//
// Empty result is the common case — most systems have no exclusions.
// Order is sorted ascending so the playbook reads deterministically.
func (s *SQLiteStore) ResolveForSystem(systemID, updaterID string) ([]string, error) {
	rows, err := s.resolveRaw(systemID, updaterID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(rows))
	out := make([]string, 0, len(rows))
	for _, e := range rows {
		if _, ok := seen[e.Pattern]; ok {
			continue
		}
		seen[e.Pattern] = struct{}{}
		out = append(out, e.Pattern)
	}
	sort.Strings(out)
	return out, nil
}

// ResolveEffectiveForSystem returns the same union but keeps the
// per-row scope so the UI can render attribution. Duplicates of the
// same pattern at different scopes all survive: the SPA shows each
// source so the operator can audit "where did this exclusion come
// from?" — picking just the first would hide that.
func (s *SQLiteStore) ResolveEffectiveForSystem(systemID, updaterID string) ([]Exclusion, error) {
	return s.resolveRaw(systemID, updaterID)
}

func (s *SQLiteStore) resolveRaw(systemID, updaterID string) ([]Exclusion, error) {
	if strings.TrimSpace(systemID) == "" || strings.TrimSpace(updaterID) == "" {
		return nil, fmt.Errorf("%w: system_id and updater required", ErrInvalid)
	}
	q := `
		SELECT id, scope, target_id, updater, pattern, reason, created_at, created_by
		FROM package_exclusions
		WHERE (updater = ? OR updater = '*')
		  AND (
		      scope = 'global'
		      OR (scope = 'system' AND target_id = ?)
		      OR (scope = 'group' AND target_id = (
		            SELECT group_id FROM hosts WHERE id = ?
		          ))
		  )
		ORDER BY
		  CASE scope WHEN 'global' THEN 0 WHEN 'group' THEN 1 ELSE 2 END,
		  created_at, id
	`
	rows, err := s.db.Query(q, updaterID, systemID, systemID)
	if err != nil {
		return nil, fmt.Errorf("exclusions: resolve: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Exclusion{}
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("exclusions: resolve scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("exclusions: resolve rows: %w", err)
	}
	return out, nil
}

// scanRow is the minimal contract Get and list share — both *sql.Row
// and *sql.Rows satisfy it.
type scanRow interface {
	Scan(dest ...any) error
}

func scan(r scanRow) (Exclusion, error) {
	var (
		e         Exclusion
		scopeStr  string
		createdNs int64
	)
	if err := r.Scan(
		&e.ID, &scopeStr, &e.TargetID, &e.Updater, &e.Pattern,
		&e.Reason, &createdNs, &e.CreatedBy,
	); err != nil {
		return Exclusion{}, err
	}
	e.Scope = Scope(scopeStr)
	e.CreatedAt = time.Unix(0, createdNs).UTC()
	return e, nil
}

// isUniqueViolation reads the SQLite UNIQUE constraint message
// portably. Mirrors the helper in internal/groups so neither package
// has to depend on the driver type directly.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
