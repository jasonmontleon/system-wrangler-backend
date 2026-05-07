// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// UserStore is the persistence boundary for accounts. The middleware and
// handlers depend on this interface; tests use stubs to avoid SQLite.
type UserStore interface {
	Count() (int, error)
	Create(username, passwordHash string) (User, error)
	GetByUsername(username string) (User, string, error)
	GetByID(id string) (User, error)
	GetHashByID(id string) (string, error)
	UpdateProfile(id, email, theme string) (User, error)
	UpdatePassword(id, passwordHash string) error
}

// SecretStore is the small slice of the meta table that the session-signing
// secret is loaded from. Kept narrow on purpose — startup-only surface.
type SecretStore interface {
	LoadSecret(key string) ([]byte, bool, error)
	SaveSecret(key string, val []byte) error
}

// SQLiteAuthStore implements both UserStore and SecretStore against the
// shared *sql.DB. Owns the users + meta table schema.
type SQLiteAuthStore struct {
	db    *sql.DB
	NewID func() string
	Now   func() time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email         TEXT NOT NULL DEFAULT '',
    theme         TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;
`

// migrate adds email/theme columns when upgrading from a pre-existing schema
// that lacked them. SQLite's ALTER TABLE ADD COLUMN is cheap and idempotent
// when guarded by an introspection check.
func (s *SQLiteAuthStore) migrate() error {
	cols, err := s.userColumns()
	if err != nil {
		return err
	}
	for _, c := range []struct{ name, ddl string }{
		{"email", `ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''`},
		{"theme", `ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT ''`},
	} {
		if _, ok := cols[c.name]; ok {
			continue
		}
		if _, err := s.db.Exec(c.ddl); err != nil {
			return fmt.Errorf("auth: migrate %s: %w", c.name, err)
		}
	}
	return nil
}

func (s *SQLiteAuthStore) userColumns() (map[string]struct{}, error) {
	rows, err := s.db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return nil, fmt.Errorf("auth: pragma table_info: %w", err)
	}
	defer func() { _ = rows.Close() }()
	cols := map[string]struct{}{}
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, fmt.Errorf("auth: pragma scan: %w", err)
		}
		cols[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: pragma rows: %w", err)
	}
	return cols, nil
}

// NewSQLiteAuthStore initializes the users + meta schema on db (creating or
// migrating columns as needed) and returns a store that owns those tables.
func NewSQLiteAuthStore(db *sql.DB) (*SQLiteAuthStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("auth: schema: %w", err)
	}
	s := &SQLiteAuthStore{
		db:    db,
		NewID: func() string { return uuid.NewString() },
		Now:   time.Now,
	}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Count returns the number of user rows. The setup flow uses zero as the
// signal that the install is uninitialized.
func (s *SQLiteAuthStore) Count() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("auth: count users: %w", err)
	}
	return n, nil
}

// Create inserts a new user with the given username and bcrypt hash.
// Returns ErrUserExists on a unique-constraint conflict.
func (s *SQLiteAuthStore) Create(username, hash string) (User, error) {
	username = strings.TrimSpace(username)
	if len(username) < MinUsernameLen {
		return User{}, fmt.Errorf("%w: username required", ErrInvalid)
	}
	u := User{
		ID:        s.NewID(),
		Username:  username,
		CreatedAt: s.Now().UTC(),
	}
	_, err := s.db.Exec(
		`INSERT INTO users (id, username, password_hash, email, theme, created_at) VALUES (?, ?, ?, '', '', ?)`,
		u.ID, u.Username, hash, u.CreatedAt.UnixNano(),
	)
	if err != nil {
		// modernc.org/sqlite returns error strings — match on substring rather
		// than driver-specific error types.
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return User{}, ErrUserExists
		}
		return User{}, fmt.Errorf("auth: insert user: %w", err)
	}
	return u, nil
}

const userSelect = `SELECT id, username, password_hash, email, theme, created_at FROM users`

// GetByUsername returns the user and its bcrypt hash, or ErrUserNotFound
// if no row matches.
func (s *SQLiteAuthStore) GetByUsername(username string) (User, string, error) {
	row := s.db.QueryRow(userSelect+` WHERE username = ?`, username)
	u, hash, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", ErrUserNotFound
	}
	return u, hash, err
}

// GetByID returns the user with the given ID, or ErrUserNotFound.
func (s *SQLiteAuthStore) GetByID(id string) (User, error) {
	row := s.db.QueryRow(userSelect+` WHERE id = ?`, id)
	u, _, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	return u, err
}

// GetHashByID returns the bcrypt hash for the user with the given ID. Used
// by the change-password flow to verify the current password without
// retrieving the full user record.
func (s *SQLiteAuthStore) GetHashByID(id string) (string, error) {
	var hash string
	err := s.db.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, id).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", fmt.Errorf("auth: load hash: %w", err)
	}
	return hash, nil
}

// UpdateProfile sets email and theme on the user row, returning the
// resulting User. ErrUserNotFound is returned if no row matches id.
func (s *SQLiteAuthStore) UpdateProfile(id, email, theme string) (User, error) {
	email = strings.TrimSpace(email)
	if !ValidTheme(theme) {
		return User{}, fmt.Errorf("%w: invalid theme", ErrInvalid)
	}
	res, err := s.db.Exec(
		`UPDATE users SET email = ?, theme = ? WHERE id = ?`,
		email, theme, id,
	)
	if err != nil {
		return User{}, fmt.Errorf("auth: update profile: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return User{}, fmt.Errorf("auth: rows affected: %w", err)
	}
	if n == 0 {
		return User{}, ErrUserNotFound
	}
	return s.GetByID(id)
}

// UpdatePassword replaces the bcrypt hash on the user row. ErrUserNotFound
// is returned if no row matches id.
func (s *SQLiteAuthStore) UpdatePassword(id, hash string) error {
	res, err := s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	if err != nil {
		return fmt.Errorf("auth: update password: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("auth: rows affected: %w", err)
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// LoadSecret reads a key from the meta table. The bool reports whether a
// row existed; err is non-nil only on a real DB error.
func (s *SQLiteAuthStore) LoadSecret(key string) ([]byte, bool, error) {
	var val []byte
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("auth: load secret %q: %w", key, err)
	}
	return val, true, nil
}

// SaveSecret upserts a key into the meta table.
func (s *SQLiteAuthStore) SaveSecret(key string, val []byte) error {
	_, err := s.db.Exec(
		`INSERT INTO meta (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, val,
	)
	if err != nil {
		return fmt.Errorf("auth: save secret %q: %w", key, err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(r rowScanner) (User, string, error) {
	var (
		u         User
		hash      string
		createdNs int64
	)
	if err := r.Scan(&u.ID, &u.Username, &hash, &u.Email, &u.Theme, &createdNs); err != nil {
		return User{}, "", err
	}
	u.CreatedAt = time.Unix(0, createdNs).UTC()
	return u, hash, nil
}
