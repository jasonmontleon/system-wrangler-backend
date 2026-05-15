// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Store owns the audit_log table. One per process, constructed once at
// startup against the shared *sql.DB and held by every handler that
// emits audit events.
type Store struct {
	db *sql.DB

	// NewID is the audit row primary key. UUIDv7 by default so ORDER BY id
	// matches ORDER BY occurred_at, which makes "recent events" range
	// scans cheap. Overridable for deterministic tests.
	NewID func() (string, error)
	// Now sources the occurred_at column. Overridable for deterministic
	// tests.
	Now func() time.Time
}

// schema is appended to whatever DDL other packages own. CREATE TABLE
// IF NOT EXISTS makes re-running on an initialized DB a no-op. STRICT
// matches the systems table so type errors fail at insert time.
const schema = `
CREATE TABLE IF NOT EXISTS audit_log (
    id            TEXT PRIMARY KEY,
    occurred_at   INTEGER NOT NULL,
    actor_kind    TEXT NOT NULL,
    actor_id      TEXT,
    actor_label   TEXT,
    action        TEXT NOT NULL,
    target_kind   TEXT,
    target_id     TEXT,
    target_label  TEXT,
    outcome       TEXT NOT NULL,
    detail        TEXT,
    request_ip    TEXT,
    request_id    TEXT
) STRICT;
CREATE INDEX IF NOT EXISTS audit_occurred_at ON audit_log(occurred_at);
CREATE INDEX IF NOT EXISTS audit_actor       ON audit_log(actor_id, occurred_at);
CREATE INDEX IF NOT EXISTS audit_target      ON audit_log(target_kind, target_id, occurred_at);
CREATE INDEX IF NOT EXISTS audit_action      ON audit_log(action, occurred_at);
`

// NewSQLiteStore runs the audit_log schema migration and returns a Store
// bound to db. Calling it twice on the same db is safe.
func NewSQLiteStore(db *sql.DB) (*Store, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("audit: schema: %w", err)
	}
	return &Store{
		db: db,
		NewID: func() (string, error) {
			id, err := uuid.NewV7()
			if err != nil {
				return "", err
			}
			return id.String(), nil
		},
		Now: time.Now,
	}, nil
}

// LogTx writes an audit row inside the caller's tx. Use this whenever
// the audited change is itself a DB write: the audit row commits with
// the change or neither commits. Failing this call is grounds for
// rolling back the surrounding transaction.
func (s *Store) LogTx(ctx context.Context, tx *sql.Tx, e Event) error {
	if tx == nil {
		return errors.New("audit: LogTx called with nil tx — use Log for non-transactional events")
	}
	return s.insert(ctx, tx, e)
}

// Log writes an audit row outside any transaction. Use only for events
// that have no surrounding DB write — failed-login attempts before the
// user is resolved, system-emitted background events. For every other
// case, prefer LogTx so the audit row can't be lost on a crash between
// the change and the log.
func (s *Store) Log(ctx context.Context, e Event) error {
	return s.insert(ctx, s.db, e)
}

// execer covers both *sql.DB and *sql.Tx so insert serves both call
// sites without duplication.
type execer interface {
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
}

func (s *Store) insert(ctx context.Context, e execer, ev Event) error {
	if ev.Action == "" {
		return errors.New("audit: Event.Action is required")
	}
	if ev.Outcome == "" {
		return errors.New("audit: Event.Outcome is required")
	}
	id := ev.ID
	if id == "" {
		generated, err := s.NewID()
		if err != nil {
			return fmt.Errorf("audit: new id: %w", err)
		}
		id = generated
	}
	actor := ActorFromContext(ctx)
	if actor.Kind == "" {
		actor.Kind = ActorUnauthenticated
	}
	var detailJSON sql.NullString
	if len(ev.Detail) > 0 {
		b, err := json.Marshal(ev.Detail)
		if err != nil {
			return fmt.Errorf("audit: marshal detail: %w", err)
		}
		detailJSON = sql.NullString{String: string(b), Valid: true}
	}
	if _, err := e.ExecContext(ctx, `
INSERT INTO audit_log (
    id, occurred_at, actor_kind, actor_id, actor_label,
    action, target_kind, target_id, target_label,
    outcome, detail, request_ip, request_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, s.Now().UTC().UnixMilli(),
		string(actor.Kind), nullStr(actor.ID), nullStr(actor.Label),
		ev.Action,
		nullStr(ev.TargetKind), nullStr(ev.TargetID), nullStr(ev.TargetLabel),
		string(ev.Outcome), detailJSON,
		nullStr(RemoteAddrFromContext(ctx)), nullStr(RequestIDFromContext(ctx)),
	); err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	return nil
}

// Record is the read-side projection of an audit_log row. Returned by
// Get / ListQuery and serialized to JSON for the read API.
type Record struct {
	ID          string         `json:"id"`
	OccurredAt  time.Time      `json:"occurredAt"`
	ActorKind   ActorKind      `json:"actorKind"`
	ActorID     string         `json:"actorId,omitempty"`
	ActorLabel  string         `json:"actorLabel,omitempty"`
	Action      string         `json:"action"`
	TargetKind  string         `json:"targetKind,omitempty"`
	TargetID    string         `json:"targetId,omitempty"`
	TargetLabel string         `json:"targetLabel,omitempty"`
	Outcome     Outcome        `json:"outcome"`
	Detail      map[string]any `json:"detail,omitempty"`
	RequestIP   string         `json:"requestIp,omitempty"`
	RequestID   string         `json:"requestId,omitempty"`
}

// Query carries the filters supported by ListQuery. Zero-value fields
// mean "no filter on this dimension."
type Query struct {
	Since       time.Time
	Until       time.Time
	ActorID     string
	ActorLabel  string // case-insensitive substring match against actor_label
	Action      string // exact or prefix when trailing '*'
	TargetKind  string
	TargetID    string
	TargetLabel string // case-insensitive substring match against target_label
	Outcome     Outcome
	RequestID   string // exact match against request_id
	Limit       int
	AfterMillis int64 // 0 = no cursor; paired with AfterID
	AfterID     string
	// Scope restricts results to rows visible to a group-only caller.
	// Nil means "no scope filter" (global-role callers). A non-nil
	// filter with an empty GroupIDs slice is the explicit "user with
	// no role assignments" state and matches zero rows.
	Scope *ScopeFilter
}

// ScopeFilter restricts ListQuery to rows whose target resolves to a
// group the caller can see. Per research/rbac.md, two row shapes
// match:
//
//   - target_kind = 'system' AND the system's current group_id is in
//     GroupIDs. The join against hosts means rows for deleted systems
//     naturally fall out (only global roles see those).
//   - target_kind = 'system_group' AND target_id is in GroupIDs.
//
// All other rows (target_kind = 'user', cross-scope actions, etc.)
// are hidden from group-only callers.
type ScopeFilter struct {
	GroupIDs []string
}

// ErrNotFound is returned by Get when no row matches the id.
var ErrNotFound = errors.New("audit: record not found")

// IsVisibleTo reports whether rec is visible to a group-only caller
// whose scope is sf. Mirrors the predicate enforced by ListQuery so
// the single-record Get endpoint can gate consistently: a row a
// group-only caller can't see via /api/admin/audit must also be
// hidden via /api/admin/audit/{id}.
//
// Rules:
//   - target_kind = 'system' is visible iff the system's current
//     group_id is in sf.GroupIDs. Deleted systems are not visible.
//   - target_kind = 'system_group' is visible iff target_id is in
//     sf.GroupIDs.
//   - any other shape is hidden (cross-scope rows, user-targets, etc.)
func (s *Store) IsVisibleTo(rec Record, sf ScopeFilter) (bool, error) {
	if rec.TargetKind == "system_group" {
		for _, gid := range sf.GroupIDs {
			if rec.TargetID == gid {
				return true, nil
			}
		}
		return false, nil
	}
	if rec.TargetKind != "system" || rec.TargetID == "" || len(sf.GroupIDs) == 0 {
		return false, nil
	}
	placeholders := strings.Repeat("?,", len(sf.GroupIDs))
	placeholders = placeholders[:len(placeholders)-1]
	// sf.GroupIDs flows through args, never SQL — gosec G201 false
	// positive on the assembled placeholder list.
	q := "SELECT 1 FROM hosts WHERE id = ? AND group_id IN (" + placeholders + ")" //nolint:gosec
	args := make([]any, 0, len(sf.GroupIDs)+1)
	args = append(args, rec.TargetID)
	for _, id := range sf.GroupIDs {
		args = append(args, id)
	}
	var x int
	switch err := s.db.QueryRow(q, args...).Scan(&x); {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("audit: visibility check: %w", err)
	}
	return true, nil
}

// Get returns one record by id, or ErrNotFound.
func (s *Store) Get(id string) (Record, error) {
	row := s.db.QueryRow(`
SELECT id, occurred_at, actor_kind, actor_id, actor_label, action,
       target_kind, target_id, target_label, outcome, detail,
       request_ip, request_id
FROM audit_log WHERE id = ?`, id)
	r, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	return r, err
}

// DefaultLimit is the page size when ListQuery is called with Limit<=0.
const DefaultLimit = 50

// MaxLimit caps ListQuery to keep accidental "limit=1000000" cheap.
const MaxLimit = 500

// ListQuery returns up to q.Limit records (default 50, cap 500) matching
// q, ordered newest-first. Keyset pagination on (occurred_at, id) keeps
// cost flat as the table grows. The hasMore return is true iff at least
// one more record exists beyond the returned slice — callers use it to
// decide whether to expose a next-page cursor.
func (s *Store) ListQuery(q Query) ([]Record, bool, error) {
	where, args := buildWhere(q)
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	// buildWhere only emits a fixed SQL fragment with parameter
	// placeholders — user input lands in `args`, never in the SQL string.
	// gosec G202 can't see that constraint statically.
	sqlStr := buildSelect(where) //nolint:gosec
	// Probe one row past the visible limit so we can tell whether a next
	// page exists without a second round-trip.
	args = append(args, limit+1)
	rows, err := s.db.Query(sqlStr, args...)
	if err != nil {
		return nil, false, fmt.Errorf("audit: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Record{}
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, false, fmt.Errorf("audit: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("audit: list rows: %w", err)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

// buildSelect splices a buildWhere clause into the list query.
// Extracted so the nolint annotation on the call site has a one-liner to
// sit on rather than a multi-line raw-string concatenation.
func buildSelect(where string) string {
	return `SELECT id, occurred_at, actor_kind, actor_id, actor_label, action,
       target_kind, target_id, target_label, outcome, detail,
       request_ip, request_id
FROM audit_log ` + where + `
ORDER BY occurred_at DESC, id DESC
LIMIT ?`
}

func buildWhere(q Query) (string, []any) {
	var (
		clauses []string
		args    []any
	)
	if !q.Since.IsZero() {
		clauses = append(clauses, "occurred_at >= ?")
		args = append(args, q.Since.UTC().UnixMilli())
	}
	if !q.Until.IsZero() {
		clauses = append(clauses, "occurred_at < ?")
		args = append(args, q.Until.UTC().UnixMilli())
	}
	if q.ActorID != "" {
		clauses = append(clauses, "actor_id = ?")
		args = append(args, q.ActorID)
	}
	if q.ActorLabel != "" {
		clauses = append(clauses, "actor_label LIKE ? ESCAPE '\\' COLLATE NOCASE")
		args = append(args, "%"+escapeLike(q.ActorLabel)+"%")
	}
	if q.Action != "" {
		if strings.HasSuffix(q.Action, "*") {
			clauses = append(clauses, "action LIKE ?")
			args = append(args, strings.TrimSuffix(q.Action, "*")+"%")
		} else {
			clauses = append(clauses, "action = ?")
			args = append(args, q.Action)
		}
	}
	if q.TargetKind != "" {
		clauses = append(clauses, "target_kind = ?")
		args = append(args, q.TargetKind)
	}
	if q.TargetID != "" {
		clauses = append(clauses, "target_id = ?")
		args = append(args, q.TargetID)
	}
	if q.TargetLabel != "" {
		clauses = append(clauses, "target_label LIKE ? ESCAPE '\\' COLLATE NOCASE")
		args = append(args, "%"+escapeLike(q.TargetLabel)+"%")
	}
	if q.Outcome != "" {
		clauses = append(clauses, "outcome = ?")
		args = append(args, string(q.Outcome))
	}
	if q.RequestID != "" {
		clauses = append(clauses, "request_id = ?")
		args = append(args, q.RequestID)
	}
	if q.AfterMillis > 0 && q.AfterID != "" {
		clauses = append(clauses, "(occurred_at < ? OR (occurred_at = ? AND id < ?))")
		args = append(args, q.AfterMillis, q.AfterMillis, q.AfterID)
	}
	if q.Scope != nil {
		clause, extra := scopeClause(q.Scope.GroupIDs)
		clauses = append(clauses, clause)
		args = append(args, extra...)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

// escapeLike escapes the three SQL LIKE wildcards (% _ \) so a user-
// supplied substring is treated as literal text. The companion LIKE
// clause must use ESCAPE '\' — but SQLite treats backslash as the
// default escape character only when the pattern contains it, so
// emitting the literal pattern here is enough at our scale. Inputs
// without wildcards round-trip unchanged.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// scopeClause builds the WHERE fragment that restricts rows to those a
// group-only caller can see. An empty groupIDs slice produces a
// constant-false clause ("1 = 0") so the user with no role assignments
// sees no rows. With placeholders embedded as a fixed-shape repeated
// IN list, the caller-supplied groupIDs flow only through args, not
// SQL strings — gosec G201 is satisfied.
func scopeClause(groupIDs []string) (string, []any) {
	if len(groupIDs) == 0 {
		return "1 = 0", nil
	}
	placeholders := strings.Repeat("?,", len(groupIDs))
	placeholders = placeholders[:len(placeholders)-1]
	clause := "((target_kind = 'system' AND target_id IN (" +
		"SELECT id FROM hosts WHERE group_id IN (" + placeholders + "))) OR " +
		"(target_kind = 'system_group' AND target_id IN (" + placeholders + ")))"
	args := make([]any, 0, len(groupIDs)*2)
	for _, id := range groupIDs {
		args = append(args, id)
	}
	for _, id := range groupIDs {
		args = append(args, id)
	}
	return clause, args
}

type rowScanner interface {
	Scan(dest ...any) error
}

// nullStr returns nil for empty strings so SQLite stores NULL rather than
// "" in the optional columns — keeps "this field was never set" distinct
// from "this field was explicitly empty" in case it ever matters.
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func scanRecord(r rowScanner) (Record, error) {
	var (
		rec        Record
		occurredMs int64
		actorID    sql.NullString
		actorLabel sql.NullString
		targetKind sql.NullString
		targetID   sql.NullString
		targetLab  sql.NullString
		detailRaw  sql.NullString
		ip         sql.NullString
		reqID      sql.NullString
		kind       string
		outcome    string
	)
	if err := r.Scan(
		&rec.ID, &occurredMs, &kind, &actorID, &actorLabel,
		&rec.Action, &targetKind, &targetID, &targetLab,
		&outcome, &detailRaw, &ip, &reqID,
	); err != nil {
		return Record{}, err
	}
	rec.OccurredAt = time.UnixMilli(occurredMs).UTC()
	rec.ActorKind = ActorKind(kind)
	rec.ActorID = actorID.String
	rec.ActorLabel = actorLabel.String
	rec.TargetKind = targetKind.String
	rec.TargetID = targetID.String
	rec.TargetLabel = targetLab.String
	rec.Outcome = Outcome(outcome)
	rec.RequestIP = ip.String
	rec.RequestID = reqID.String
	if detailRaw.Valid && detailRaw.String != "" {
		if err := json.Unmarshal([]byte(detailRaw.String), &rec.Detail); err != nil {
			return Record{}, fmt.Errorf("audit: scan detail: %w", err)
		}
	}
	return rec, nil
}
