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
	id, err := s.NewID()
	if err != nil {
		return fmt.Errorf("audit: new id: %w", err)
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
	_, err = e.ExecContext(ctx, `
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
	)
	if err != nil {
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
	Action      string // exact or prefix when trailing '*'
	TargetKind  string
	TargetID    string
	Outcome     Outcome
	Limit       int
	AfterMillis int64 // 0 = no cursor; paired with AfterID
	AfterID     string
}

// ErrNotFound is returned by Get when no row matches the id.
var ErrNotFound = errors.New("audit: record not found")

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
// cost flat as the table grows.
func (s *Store) ListQuery(q Query) ([]Record, error) {
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
	args = append(args, limit)
	rows, err := s.db.Query(sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Record{}
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("audit: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: list rows: %w", err)
	}
	return out, nil
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
	if q.Outcome != "" {
		clauses = append(clauses, "outcome = ?")
		args = append(args, string(q.Outcome))
	}
	if q.AfterMillis > 0 && q.AfterID != "" {
		clauses = append(clauses, "(occurred_at < ? OR (occurred_at = ? AND id < ?))")
		args = append(args, q.AfterMillis, q.AfterMillis, q.AfterID)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
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
