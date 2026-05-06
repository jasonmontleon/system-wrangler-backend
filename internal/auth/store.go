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
    created_at    INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;
`

func NewSQLiteAuthStore(db *sql.DB) (*SQLiteAuthStore, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("auth: schema: %w", err)
	}
	return &SQLiteAuthStore{
		db:    db,
		NewID: func() string { return uuid.NewString() },
		Now:   time.Now,
	}, nil
}

func (s *SQLiteAuthStore) Count() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("auth: count users: %w", err)
	}
	return n, nil
}

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
		`INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)`,
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

func (s *SQLiteAuthStore) GetByUsername(username string) (User, string, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, created_at FROM users WHERE username = ?`,
		username,
	)
	u, hash, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, "", ErrUserNotFound
	}
	return u, hash, err
}

func (s *SQLiteAuthStore) GetByID(id string) (User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, created_at FROM users WHERE id = ?`,
		id,
	)
	u, _, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	return u, err
}

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
	if err := r.Scan(&u.ID, &u.Username, &hash, &createdNs); err != nil {
		return User{}, "", err
	}
	u.CreatedAt = time.Unix(0, createdNs).UTC()
	return u, hash, nil
}
