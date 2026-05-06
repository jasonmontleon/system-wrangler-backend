// SPDX-License-Identifier: AGPL-3.0-or-later

package inventory

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore is a Store backed by a single SQLite database file.
// In-memory databases ("file::memory:?cache=shared") work for tests, but
// per-test files via t.TempDir() are simpler and exercise the same code path.
type SQLiteStore struct {
	db *sql.DB

	// Same injection points as MemStore so tests stay deterministic.
	NewID func() string
	Now   func() time.Time
}

// OpenSQLite opens (or creates) the DB at dsn, applies safe defaults, and
// ensures the schema exists. Caller owns the returned *SQLiteStore and must
// Close it on shutdown.
func OpenSQLite(dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("inventory: open %q: %w", dsn, err)
	}
	// SQLite serializes writes; one conn keeps :memory: tests sane and is
	// plenty for fleet-management write rates.
	db.SetMaxOpenConns(1)

	for _, p := range []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA busy_timeout=5000`,
	} {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("inventory: %s: %w", p, err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("inventory: schema: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

// Unix nanoseconds for timestamps: trivial to sort, no parsing on read,
// round-trips Go's time.Time without precision loss. NULL last_seen = never.
const schema = `
CREATE TABLE IF NOT EXISTS hosts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    hostname    TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    status      TEXT NOT NULL,
    last_seen   INTEGER
) STRICT;

CREATE INDEX IF NOT EXISTS hosts_created_at ON hosts(created_at, id);
`

func (s *SQLiteStore) Create(in HostInput) (Host, error) {
	if err := in.Validate(); err != nil {
		return Host{}, err
	}
	h := Host{
		ID:        s.NewID(),
		Name:      strings.TrimSpace(in.Name),
		Hostname:  strings.TrimSpace(in.Hostname),
		CreatedAt: s.Now().UTC(),
		Status:    StatusUnprobed,
	}
	_, err := s.db.Exec(
		`INSERT INTO hosts (id, name, hostname, created_at, status) VALUES (?, ?, ?, ?, ?)`,
		h.ID, h.Name, h.Hostname, h.CreatedAt.UnixNano(), string(h.Status),
	)
	if err != nil {
		return Host{}, fmt.Errorf("inventory: insert host: %w", err)
	}
	return h, nil
}

func (s *SQLiteStore) Get(id string) (Host, error) {
	row := s.db.QueryRow(
		`SELECT id, name, hostname, created_at, status, last_seen FROM hosts WHERE id = ?`,
		id,
	)
	h, err := scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	return h, err
}

// List returns hosts ordered by created_at asc with id as tiebreaker, matching
// MemStore so handler behavior is identical regardless of backend.
func (s *SQLiteStore) List() ([]Host, error) {
	rows, err := s.db.Query(
		`SELECT id, name, hostname, created_at, status, last_seen FROM hosts ORDER BY created_at, id`,
	)
	if err != nil {
		return nil, fmt.Errorf("inventory: list: %w", err)
	}
	defer rows.Close()

	out := []Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("inventory: scan host: %w", err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: list rows: %w", err)
	}
	return out, nil
}

func (s *SQLiteStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM hosts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("inventory: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateProbe mirrors MemStore: success sets Status + LastSeen; failure sets
// Status only, preserving any prior LastSeen.
func (s *SQLiteStore) UpdateProbe(id string, ok bool, when time.Time) error {
	when = when.UTC()
	var (
		res sql.Result
		err error
	)
	if ok {
		res, err = s.db.Exec(
			`UPDATE hosts SET status = ?, last_seen = ? WHERE id = ?`,
			string(StatusReachable), when.UnixNano(), id,
		)
	} else {
		res, err = s.db.Exec(
			`UPDATE hosts SET status = ? WHERE id = ?`,
			string(StatusUnreachable), id,
		)
	}
	if err != nil {
		return fmt.Errorf("inventory: update probe: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// rowScanner unifies *sql.Row and *sql.Rows so scanHost serves Get and List.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanHost(r rowScanner) (Host, error) {
	var (
		h         Host
		createdNs int64
		lastSeen  sql.NullInt64
		status    string
	)
	if err := r.Scan(&h.ID, &h.Name, &h.Hostname, &createdNs, &status, &lastSeen); err != nil {
		return Host{}, err
	}
	h.CreatedAt = time.Unix(0, createdNs).UTC()
	h.Status = Status(status)
	if lastSeen.Valid {
		t := time.Unix(0, lastSeen.Int64).UTC()
		h.LastSeen = &t
	}
	return h, nil
}
