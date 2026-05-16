// SPDX-License-Identifier: Apache-2.0

package hostkeys

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Store is the persistence boundary for host-key rows. SQLiteStore
// below is the production implementation; the resolver and tests in
// downstream packages can compose against this interface.
type Store interface {
	// List returns every row for the supplied system, ordered by
	// state (accepted first, then pending) and algorithm.
	List(systemID string) ([]HostKey, error)
	// AcceptedFor returns just the accepted rows for the system —
	// the exec wrapper uses these to build a per-run known_hosts.
	// Returns an empty slice (not an error) when none are accepted;
	// callers that demand at least one key check for empty.
	AcceptedFor(systemID string) ([]HostKey, error)
	// Get returns one row by primary key. Used by Delete to figure
	// out which audit action to emit (reject vs delete).
	Get(id string) (HostKey, error)
	// RecordPending upserts a pending row for the (system_id,
	// algorithm) pair. If a pending row exists with a different
	// fingerprint, the new fingerprint wins — the operator was
	// going to see one prompt either way. If a pending row exists
	// with the same fingerprint, first_seen_at is preserved so the
	// banner can show "first offered at ...".
	RecordPending(systemID, algorithm, publicKey, fingerprint string) (HostKey, error)
	// Accept promotes a pending row to accepted. If an accepted
	// row already exists for the same (system_id, algorithm), it
	// is replaced atomically and the returned bool reports
	// `replaced=true` so the caller can pick the right audit
	// action. The fingerprint argument must match the pending
	// row's current fingerprint (defeats stale-banner accepts);
	// returns ErrFingerprintStale otherwise.
	Accept(systemID, algorithm, fingerprint, acceptedBy string) (HostKey, bool, error)
	// Delete removes one row by primary key. Returns ErrNotFound
	// if no row exists. The handler emits a different audit
	// action depending on the row's state (reject for pending,
	// delete for accepted).
	Delete(id string) error
}

// SQLiteStore persists host keys to SQLite. The UNIQUE constraint
// on (system_id, state, algorithm) is what makes RecordPending and
// Accept transactional without explicit locking — a duplicate
// insert collides at the constraint and the retry path is the
// upsert.
type SQLiteStore struct {
	db *sql.DB

	NewID func() string
	Now   func() time.Time
}

// NewSQLiteStore migrates the schema and returns a Store. Idempotent.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("hostkeys: schema: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS system_host_keys (
    id            TEXT    PRIMARY KEY,
    system_id     TEXT    NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    state         TEXT    NOT NULL CHECK (state IN ('accepted', 'pending')),
    algorithm     TEXT    NOT NULL,
    public_key    TEXT    NOT NULL,
    fingerprint   TEXT    NOT NULL,
    first_seen_at INTEGER NOT NULL,
    accepted_at   INTEGER,
    accepted_by   TEXT,
    UNIQUE (system_id, state, algorithm)
) STRICT;

CREATE INDEX IF NOT EXISTS system_host_keys_system ON system_host_keys(system_id);
`

// List satisfies Store.List against the underlying SQLite table.
func (s *SQLiteStore) List(systemID string) ([]HostKey, error) {
	rows, err := s.db.Query(
		`SELECT id, system_id, state, algorithm, public_key, fingerprint,
		        first_seen_at, accepted_at, accepted_by
		 FROM system_host_keys
		 WHERE system_id = ?
		 ORDER BY
		   CASE state WHEN 'accepted' THEN 0 ELSE 1 END,
		   algorithm`,
		systemID,
	)
	if err != nil {
		return nil, fmt.Errorf("hostkeys: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []HostKey{}
	for rows.Next() {
		hk, err := scanHostKey(rows)
		if err != nil {
			return nil, fmt.Errorf("hostkeys: scan: %w", err)
		}
		out = append(out, hk)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("hostkeys: rows: %w", err)
	}
	return out, nil
}

// AcceptedFor satisfies Store.AcceptedFor.
func (s *SQLiteStore) AcceptedFor(systemID string) ([]HostKey, error) {
	rows, err := s.db.Query(
		`SELECT id, system_id, state, algorithm, public_key, fingerprint,
		        first_seen_at, accepted_at, accepted_by
		 FROM system_host_keys
		 WHERE system_id = ? AND state = 'accepted'
		 ORDER BY algorithm`,
		systemID,
	)
	if err != nil {
		return nil, fmt.Errorf("hostkeys: accepted_for: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []HostKey{}
	for rows.Next() {
		hk, err := scanHostKey(rows)
		if err != nil {
			return nil, fmt.Errorf("hostkeys: scan: %w", err)
		}
		out = append(out, hk)
	}
	return out, rows.Err()
}

// Get satisfies Store.Get.
func (s *SQLiteStore) Get(id string) (HostKey, error) {
	row := s.db.QueryRow(
		`SELECT id, system_id, state, algorithm, public_key, fingerprint,
		        first_seen_at, accepted_at, accepted_by
		 FROM system_host_keys
		 WHERE id = ?`,
		id,
	)
	hk, err := scanHostKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return HostKey{}, ErrNotFound
	}
	return hk, err
}

// RecordPending satisfies Store.RecordPending.
func (s *SQLiteStore) RecordPending(systemID, algorithm, publicKey, fingerprint string) (HostKey, error) {
	systemID = strings.TrimSpace(systemID)
	algorithm = strings.TrimSpace(algorithm)
	publicKey = strings.TrimSpace(publicKey)
	fingerprint = strings.TrimSpace(fingerprint)
	if systemID == "" || algorithm == "" || publicKey == "" || fingerprint == "" {
		return HostKey{}, fmt.Errorf("%w: system_id, algorithm, public_key, fingerprint required", ErrInvalid)
	}
	now := s.Now().UTC()
	existing, err := s.findByScope(systemID, StatePending, algorithm)
	switch {
	case errors.Is(err, ErrNotFound):
		id := s.NewID()
		if _, err := s.db.Exec(
			`INSERT INTO system_host_keys
				(id, system_id, state, algorithm, public_key, fingerprint, first_seen_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, systemID, string(StatePending), algorithm, publicKey, fingerprint, now.UnixNano(),
		); err != nil {
			return HostKey{}, fmt.Errorf("hostkeys: insert pending: %w", err)
		}
		return HostKey{
			ID:          id,
			SystemID:    systemID,
			State:       StatePending,
			Algorithm:   algorithm,
			PublicKey:   publicKey,
			Fingerprint: fingerprint,
			FirstSeenAt: now,
		}, nil
	case err != nil:
		return HostKey{}, err
	}
	// Pending row exists. If fingerprint matches, keep first_seen_at
	// (the operator's banner shows "first offered at ..."). If it
	// changed mid-flight, overwrite and reset first_seen_at —
	// whatever they're about to look at is the new key.
	if existing.Fingerprint == fingerprint {
		return existing, nil
	}
	if _, err := s.db.Exec(
		`UPDATE system_host_keys
		 SET public_key = ?, fingerprint = ?, first_seen_at = ?
		 WHERE id = ?`,
		publicKey, fingerprint, now.UnixNano(), existing.ID,
	); err != nil {
		return HostKey{}, fmt.Errorf("hostkeys: update pending: %w", err)
	}
	existing.PublicKey = publicKey
	existing.Fingerprint = fingerprint
	existing.FirstSeenAt = now
	return existing, nil
}

// Accept satisfies Store.Accept.
func (s *SQLiteStore) Accept(systemID, algorithm, fingerprint, acceptedBy string) (HostKey, bool, error) {
	if systemID == "" || algorithm == "" || fingerprint == "" {
		return HostKey{}, false, fmt.Errorf("%w: system_id, algorithm, fingerprint required", ErrInvalid)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return HostKey{}, false, fmt.Errorf("hostkeys: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	pending, err := scanHostKey(tx.QueryRow(
		`SELECT id, system_id, state, algorithm, public_key, fingerprint,
		        first_seen_at, accepted_at, accepted_by
		 FROM system_host_keys
		 WHERE system_id = ? AND state = 'pending' AND algorithm = ?`,
		systemID, algorithm,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return HostKey{}, false, ErrNotFound
	}
	if err != nil {
		return HostKey{}, false, fmt.Errorf("hostkeys: load pending: %w", err)
	}
	if pending.Fingerprint != fingerprint {
		return HostKey{}, false, ErrFingerprintStale
	}

	replaced := false
	if _, err := tx.Exec(
		`DELETE FROM system_host_keys WHERE system_id = ? AND state = 'accepted' AND algorithm = ?`,
		systemID, algorithm,
	); err != nil {
		return HostKey{}, false, fmt.Errorf("hostkeys: delete prior accepted: %w", err)
	}
	// Did we replace anything? RowsAffected after the DELETE tells
	// us whether an accepted row existed. tx.Exec returns the same
	// Result either way; query separately to keep this clear.
	var priorCount int
	if err := tx.QueryRow(
		`SELECT changes()`,
	).Scan(&priorCount); err != nil {
		return HostKey{}, false, fmt.Errorf("hostkeys: changes(): %w", err)
	}
	if priorCount > 0 {
		replaced = true
	}

	now := s.Now().UTC()
	if _, err := tx.Exec(
		`UPDATE system_host_keys
		 SET state = 'accepted', accepted_at = ?, accepted_by = ?
		 WHERE id = ?`,
		now.UnixNano(), acceptedBy, pending.ID,
	); err != nil {
		return HostKey{}, false, fmt.Errorf("hostkeys: promote: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return HostKey{}, false, fmt.Errorf("hostkeys: commit: %w", err)
	}
	pending.State = StateAccepted
	pending.AcceptedAt = &now
	pending.AcceptedBy = acceptedBy
	return pending, replaced, nil
}

// Delete satisfies Store.Delete.
func (s *SQLiteStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM system_host_keys WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("hostkeys: delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("hostkeys: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) findByScope(systemID string, state State, algorithm string) (HostKey, error) {
	row := s.db.QueryRow(
		`SELECT id, system_id, state, algorithm, public_key, fingerprint,
		        first_seen_at, accepted_at, accepted_by
		 FROM system_host_keys
		 WHERE system_id = ? AND state = ? AND algorithm = ?`,
		systemID, string(state), algorithm,
	)
	hk, err := scanHostKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return HostKey{}, ErrNotFound
	}
	return hk, err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanHostKey(s scanner) (HostKey, error) {
	var (
		hk         HostKey
		state      string
		firstSeen  int64
		acceptedAt sql.NullInt64
		acceptedBy sql.NullString
	)
	if err := s.Scan(
		&hk.ID, &hk.SystemID, &state, &hk.Algorithm, &hk.PublicKey, &hk.Fingerprint,
		&firstSeen, &acceptedAt, &acceptedBy,
	); err != nil {
		return HostKey{}, err
	}
	hk.State = State(state)
	hk.FirstSeenAt = time.Unix(0, firstSeen).UTC()
	if acceptedAt.Valid {
		t := time.Unix(0, acceptedAt.Int64).UTC()
		hk.AcceptedAt = &t
	}
	if acceptedBy.Valid {
		hk.AcceptedBy = acceptedBy.String
	}
	return hk, nil
}
