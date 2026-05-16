// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Store is the persistence boundary for ansible credential slots. The
// SQLiteStore below is the production implementation; tests in
// downstream packages can mock against this interface without
// pulling SQLite in.
type Store interface {
	GetByScope(kind ScopeKind, scopeID string) (Slot, error)
	List() ([]Slot, error)
	Upsert(slot Slot) (Slot, error)
	Delete(kind ScopeKind, scopeID string) error
}

// SQLiteStore persists slots to SQLite. It owns the
// ansible_credentials table. Slots are keyed by (scope_kind,
// scope_id); the UNIQUE index uses COALESCE(scope_id, "") so a NULL
// scope_id for the global slot still dedupes correctly — the same
// trick rbac.user_roles uses for global role rows.
type SQLiteStore struct {
	db *sql.DB

	NewID func() string
	Now   func() time.Time
}

// NewSQLiteStore migrates the schema and returns a Store. Idempotent
// on already-initialised databases.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("credentials: schema: %w", err)
	}
	return &SQLiteStore{db: db, NewID: newUUID, Now: time.Now}, nil
}

// schema creates the table, its uniqueness index, and the two
// cascade triggers. scope_id is a plain TEXT column that points at
// either hosts(id) or system_groups(id) depending on scope_kind —
// SQLite FKs target a single table so we can't express the cascade
// declaratively. The triggers achieve the same effect atomically,
// firing in the same transaction as the parent delete so no orphan
// window exists. CREATE TRIGGER IF NOT EXISTS keeps the migration
// idempotent across boots.
//
// The triggers depend on the hosts and system_groups tables
// existing at migration time. Production wiring in cmd/server/main.go
// initialises systems and groups stores before credentials so
// that's guaranteed; tests follow the same order.
const schema = `
CREATE TABLE IF NOT EXISTS ansible_credentials (
    id                       TEXT    PRIMARY KEY,
    scope_kind               TEXT    NOT NULL CHECK (scope_kind IN ('global', 'group', 'system')),
    scope_id                 TEXT,
    ansible_user             TEXT,
    public_key               TEXT,
    private_key_ciphertext   BLOB,
    private_key_nonce        BLOB,
    private_key_version      INTEGER,
    origin                   TEXT    CHECK (origin IS NULL OR origin IN ('sw_generated', 'user_supplied')),
    created_at               INTEGER NOT NULL,
    updated_at               INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS ansible_credentials_scope
    ON ansible_credentials(scope_kind, COALESCE(scope_id, ''));

CREATE TRIGGER IF NOT EXISTS ansible_credentials_cleanup_host
    AFTER DELETE ON hosts
    FOR EACH ROW
    BEGIN
        DELETE FROM ansible_credentials
        WHERE scope_kind = 'system' AND scope_id = OLD.id;
    END;

CREATE TRIGGER IF NOT EXISTS ansible_credentials_cleanup_group
    AFTER DELETE ON system_groups
    FOR EACH ROW
    BEGIN
        DELETE FROM ansible_credentials
        WHERE scope_kind = 'group' AND scope_id = OLD.id;
    END;
`

// GetByScope returns the slot for (kind, scopeID) or ErrNotFound.
// scopeID must be empty for ScopeGlobal.
func (s *SQLiteStore) GetByScope(kind ScopeKind, scopeID string) (Slot, error) {
	if !kind.IsValid() {
		return Slot{}, fmt.Errorf("%w: scope_kind", ErrInvalid)
	}
	row := s.db.QueryRow(
		`SELECT id, scope_kind, scope_id, ansible_user, public_key,
		        private_key_ciphertext, private_key_nonce, private_key_version,
		        origin, created_at, updated_at
		 FROM ansible_credentials
		 WHERE scope_kind = ? AND COALESCE(scope_id, '') = ?`,
		string(kind), scopeID,
	)
	slot, err := scanSlot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Slot{}, ErrNotFound
	}
	return slot, err
}

// List returns every slot, ordered by scope_kind (global, then
// group, then system) and id as tiebreaker. Intended for the
// admin overview UI.
func (s *SQLiteStore) List() ([]Slot, error) {
	rows, err := s.db.Query(
		`SELECT id, scope_kind, scope_id, ansible_user, public_key,
		        private_key_ciphertext, private_key_nonce, private_key_version,
		        origin, created_at, updated_at
		 FROM ansible_credentials
		 ORDER BY
		   CASE scope_kind WHEN 'global' THEN 0 WHEN 'group' THEN 1 WHEN 'system' THEN 2 END,
		   id`,
	)
	if err != nil {
		return nil, fmt.Errorf("credentials: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Slot{}
	for rows.Next() {
		slot, err := scanSlot(rows)
		if err != nil {
			return nil, fmt.Errorf("credentials: scan: %w", err)
		}
		out = append(out, slot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("credentials: rows: %w", err)
	}
	return out, nil
}

// Upsert inserts a new slot or updates the existing slot at the
// supplied scope. The ID on the input is ignored when an existing
// row is updated; CreatedAt is preserved on update so the audit
// trail retains the original first-set time.
func (s *SQLiteStore) Upsert(slot Slot) (Slot, error) {
	slot.AnsibleUser = strings.TrimSpace(slot.AnsibleUser)
	if err := slot.Validate(); err != nil {
		return Slot{}, fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	now := s.Now().UTC()
	existing, err := s.GetByScope(slot.ScopeKind, slot.ScopeID)
	switch {
	case errors.Is(err, ErrNotFound):
		// Insert path.
		slot.ID = s.NewID()
		slot.CreatedAt = now
		slot.UpdatedAt = now
		if _, err := s.db.Exec(
			`INSERT INTO ansible_credentials
				(id, scope_kind, scope_id, ansible_user, public_key,
				 private_key_ciphertext, private_key_nonce, private_key_version,
				 origin, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			slot.ID, string(slot.ScopeKind), nullString(slot.ScopeID),
			nullString(slot.AnsibleUser), nullString(slot.PublicKey),
			nullBlob(slot.PrivateKey.Ciphertext), nullBlob(slot.PrivateKey.Nonce),
			nullVersion(slot.PrivateKey),
			nullString(string(slot.Origin)),
			now.UnixNano(), now.UnixNano(),
		); err != nil {
			return Slot{}, fmt.Errorf("credentials: insert: %w", err)
		}
		return slot, nil
	case err != nil:
		return Slot{}, err
	}
	// Update path: keep id + created_at, refresh everything else.
	slot.ID = existing.ID
	slot.CreatedAt = existing.CreatedAt
	slot.UpdatedAt = now
	if _, err := s.db.Exec(
		`UPDATE ansible_credentials SET
			ansible_user = ?,
			public_key = ?,
			private_key_ciphertext = ?,
			private_key_nonce = ?,
			private_key_version = ?,
			origin = ?,
			updated_at = ?
		 WHERE id = ?`,
		nullString(slot.AnsibleUser), nullString(slot.PublicKey),
		nullBlob(slot.PrivateKey.Ciphertext), nullBlob(slot.PrivateKey.Nonce),
		nullVersion(slot.PrivateKey),
		nullString(string(slot.Origin)),
		now.UnixNano(), slot.ID,
	); err != nil {
		return Slot{}, fmt.Errorf("credentials: update: %w", err)
	}
	return slot, nil
}

// Delete removes the slot for (kind, scopeID). Returns ErrNotFound
// if no row exists at that scope.
func (s *SQLiteStore) Delete(kind ScopeKind, scopeID string) error {
	if !kind.IsValid() {
		return fmt.Errorf("%w: scope_kind", ErrInvalid)
	}
	res, err := s.db.Exec(
		`DELETE FROM ansible_credentials
		 WHERE scope_kind = ? AND COALESCE(scope_id, '') = ?`,
		string(kind), scopeID,
	)
	if err != nil {
		return fmt.Errorf("credentials: delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("credentials: rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// scanner abstracts over *sql.Row and *sql.Rows so scanSlot can serve
// both Get and List paths.
type scanner interface {
	Scan(dest ...any) error
}

func scanSlot(s scanner) (Slot, error) {
	var (
		slot      Slot
		scopeID   sql.NullString
		user      sql.NullString
		pub       sql.NullString
		ct        []byte
		nonce     []byte
		ver       sql.NullInt64
		origin    sql.NullString
		createdAt int64
		updatedAt int64
		scopeKind string
	)
	if err := s.Scan(
		&slot.ID, &scopeKind, &scopeID, &user, &pub,
		&ct, &nonce, &ver, &origin,
		&createdAt, &updatedAt,
	); err != nil {
		return Slot{}, err
	}
	slot.ScopeKind = ScopeKind(scopeKind)
	if scopeID.Valid {
		slot.ScopeID = scopeID.String
	}
	if user.Valid {
		slot.AnsibleUser = user.String
	}
	if pub.Valid {
		slot.PublicKey = pub.String
	}
	if len(ct) > 0 {
		slot.PrivateKey = Sealed{
			Ciphertext: ct,
			Nonce:      nonce,
			Version:    int(ver.Int64),
		}
	}
	if origin.Valid {
		slot.Origin = Origin(origin.String)
	}
	slot.CreatedAt = time.Unix(0, createdAt).UTC()
	slot.UpdatedAt = time.Unix(0, updatedAt).UTC()
	return slot, nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullBlob(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nullVersion(s Sealed) any {
	if s.IsZero() {
		return nil
	}
	return s.Version
}
