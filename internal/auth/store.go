// SPDX-License-Identifier: Apache-2.0

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
	CountEnabled() (int, error)
	Create(username, passwordHash string) (User, error)
	GetByUsername(username string) (User, string, error)
	GetByID(id string) (User, error)
	GetHashByID(id string) (string, error)
	UpdateProfile(id, email, theme string) (User, error)
	UpdatePassword(id, passwordHash string) error
	// UpdatePasswordTx is the in-transaction sibling of UpdatePassword.
	// The change-password handler uses it so the password update and the
	// `auth.password.change` audit row commit together or neither
	// commits. A nil tx falls back to UpdatePassword.
	UpdatePasswordTx(tx *sql.Tx, id, passwordHash string) error
	ListUsers() ([]User, error)
	SetDisabled(id string, disabled bool, now time.Time) (User, error)
	Delete(id string) error
	RecordLoginFailure(id string, lockedUntil *time.Time) (int, error)
	ClearLoginFailures(id string) error
	AdminSetPassword(id, passwordHash string) error
	AdminResetTOTP(id string) error
}

// TOTPState is the row-level shape returned by GetTOTPState — one round-trip
// for every field the verify path needs (enabled flag, sealed secret, sealed
// pending secret, current epoch, last consumed step).
type TOTPState struct {
	Enabled  bool
	Secret   Sealed
	Pending  Sealed
	Epoch    int64
	LastStep int64
}

// TOTPStore is the slice of persistence the TOTP enrollment + verification
// flow needs. Kept narrow so tests can supply a stub without implementing
// the whole DeviceStore/RecoveryStore surface. The *Tx variants commit
// the row change inside the handler's audit transaction so the change
// and its audit row land atomically.
type TOTPStore interface {
	SetPendingSecret(userID string, s Sealed) error
	ActivateTOTP(userID string, s Sealed, confirmedAt time.Time) error
	ActivateTOTPTx(tx *sql.Tx, userID string, s Sealed, confirmedAt time.Time) error
	DisableTOTP(userID string) error
	DisableTOTPTx(tx *sql.Tx, userID string) error
	GetTOTPState(userID string) (TOTPState, error)
	ConsumeStep(userID string, step int64) error
}

// RecoveryStore persists the bcrypt-hashed recovery codes and the one-shot
// consumption marker that turns a code into a single-use credential. The
// Tx variants share the handler's transaction with the audit row, so a
// recovery-code consumption and its `auth.totp.recovery.use` audit row
// commit together.
type RecoveryStore interface {
	InsertRecoveryCodes(userID string, hashes []string) error
	InsertRecoveryCodesTx(tx *sql.Tx, userID string, hashes []string) error
	ConsumeRecoveryCode(userID, presented string, now time.Time) error
	ConsumeRecoveryCodeTx(tx *sql.Tx, userID, presented string, now time.Time) error
	DeleteRecoveryCodes(userID string) error
}

// DeviceStore persists trusted-device rows. The cookie body carries the id
// + epoch; the store is consulted to confirm the row still exists, the epoch
// matches, and the device hasn't expired.
type DeviceStore interface {
	InsertDevice(d TrustedDevice) error
	GetDevice(id string) (TrustedDevice, error)
	ListDevices(userID string) ([]TrustedDevice, error)
	DeleteDevice(id, userID string) error
	DeleteDevicesForUser(userID string) error
	TouchDevice(id string, lastUsed time.Time) error
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

	// PostDelete, if set, runs inside the user-delete transaction
	// after the users-row DELETE (and therefore after the FK cascade
	// on dependent tables like user_roles). Returning a non-nil error
	// rolls the tx back. Wired in main.go to enforce the
	// last-global-admin guard via rbac.EnsureGlobalAdminRemains.
	PostDelete func(tx *sql.Tx, userID string) error
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

CREATE TABLE IF NOT EXISTS trusted_devices (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    label         TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    totp_epoch    INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS trusted_devices_user_idx ON trusted_devices(user_id);

CREATE TABLE IF NOT EXISTS recovery_codes (
    user_id   TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    used_at   INTEGER,
    PRIMARY KEY (user_id, code_hash)
) STRICT;
`

// migrate adds new user columns when upgrading from an older schema. SQLite's
// ALTER TABLE ADD COLUMN is cheap and idempotent when guarded by an
// introspection check.
func (s *SQLiteAuthStore) migrate() error {
	cols, err := s.userColumns()
	if err != nil {
		return err
	}
	for _, c := range []struct{ name, ddl string }{
		{"email", `ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''`},
		{"theme", `ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT ''`},
		{"totp_secret", `ALTER TABLE users ADD COLUMN totp_secret BLOB`},
		{"totp_secret_nonce", `ALTER TABLE users ADD COLUMN totp_secret_nonce BLOB`},
		{"totp_secret_version", `ALTER TABLE users ADD COLUMN totp_secret_version INTEGER`},
		{"totp_pending_secret", `ALTER TABLE users ADD COLUMN totp_pending_secret BLOB`},
		{"totp_pending_secret_nonce", `ALTER TABLE users ADD COLUMN totp_pending_secret_nonce BLOB`},
		{"totp_pending_secret_version", `ALTER TABLE users ADD COLUMN totp_pending_secret_version INTEGER`},
		{"totp_enabled", `ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`},
		{"totp_confirmed_at", `ALTER TABLE users ADD COLUMN totp_confirmed_at INTEGER`},
		{"totp_epoch", `ALTER TABLE users ADD COLUMN totp_epoch INTEGER NOT NULL DEFAULT 0`},
		{"totp_last_step", `ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0`},
		{"disabled_at", `ALTER TABLE users ADD COLUMN disabled_at INTEGER`},
		{"failed_attempts", `ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0`},
		{"locked_until", `ALTER TABLE users ADD COLUMN locked_until INTEGER`},
		{"must_change_password", `ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0`},
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

// CountEnabled returns the number of users whose disabled_at is NULL. The
// admin handler uses this to refuse a disable that would leave the install
// with zero enabled users (and therefore no one who can log in).
func (s *SQLiteAuthStore) CountEnabled() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE disabled_at IS NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("auth: count enabled users: %w", err)
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

const userSelect = `SELECT id, username, password_hash, email, theme, created_at, totp_enabled, disabled_at, failed_attempts, locked_until, must_change_password FROM users`

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

// UpdatePassword replaces the bcrypt hash on the user row, clears the
// must_change_password flag, and resets the lockout counters. The
// caller is expected to have already verified the user's current
// credential — this is the "user is voluntarily setting their own
// password" path. ErrUserNotFound is returned if no row matches id.
func (s *SQLiteAuthStore) UpdatePassword(id, hash string) error {
	return s.updatePasswordWith(s.db, id, hash)
}

// UpdatePasswordTx is the in-transaction sibling: same SQL, but the row
// change rides inside the caller's tx so the audit row that records the
// change can commit alongside it. nil tx falls back to UpdatePassword.
func (s *SQLiteAuthStore) UpdatePasswordTx(tx *sql.Tx, id, hash string) error {
	if tx == nil {
		return s.UpdatePassword(id, hash)
	}
	return s.updatePasswordWith(tx, id, hash)
}

// execer covers *sql.DB and *sql.Tx so the password-update SQL can be
// shared between the transactional and non-transactional call sites
// without duplicating the multi-column UPDATE.
type execer interface {
	Exec(q string, args ...any) (sql.Result, error)
}

func (s *SQLiteAuthStore) updatePasswordWith(e execer, id, hash string) error {
	res, err := e.Exec(
		`UPDATE users
		   SET password_hash = ?,
		       must_change_password = 0,
		       failed_attempts = 0,
		       locked_until = NULL
		 WHERE id = ?`,
		hash, id,
	)
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

// RecordLoginFailure increments failed_attempts on the user row and, if
// lockedUntil is non-nil, stamps locked_until. Returns the new attempts
// count so callers can decide whether to lock (the caller computes the
// policy; the store just persists the result). ErrUserNotFound when
// no row matches id.
func (s *SQLiteAuthStore) RecordLoginFailure(id string, lockedUntil *time.Time) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("auth: begin record failure: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	switch err := tx.QueryRow(`SELECT failed_attempts FROM users WHERE id = ?`, id).Scan(&n); {
	case errors.Is(err, sql.ErrNoRows):
		return 0, ErrUserNotFound
	case err != nil:
		return 0, fmt.Errorf("auth: read failures: %w", err)
	}
	n++
	if lockedUntil != nil {
		_, err = tx.Exec(
			`UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?`,
			n, lockedUntil.UTC().UnixNano(), id,
		)
	} else {
		_, err = tx.Exec(
			`UPDATE users SET failed_attempts = ? WHERE id = ?`,
			n, id,
		)
	}
	if err != nil {
		return 0, fmt.Errorf("auth: write failure: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("auth: commit failure: %w", err)
	}
	return n, nil
}

// ClearLoginFailures resets failed_attempts to 0 and clears locked_until.
// Called on every successful authentication path (password+TOTP, recovery
// code, trusted device) and by admin override endpoints. Idempotent —
// clearing an already-clear row succeeds.
func (s *SQLiteAuthStore) ClearLoginFailures(id string) error {
	res, err := s.db.Exec(
		`UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("auth: clear failures: %w", err)
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

// AdminSetPassword overwrites a user's bcrypt hash, sets the
// must_change_password flag so the user is forced through the
// change-password flow at next login, and clears lockout counters. All
// in a single transaction.
func (s *SQLiteAuthStore) AdminSetPassword(id, hash string) error {
	res, err := s.db.Exec(
		`UPDATE users
		   SET password_hash = ?,
		       must_change_password = 1,
		       failed_attempts = 0,
		       locked_until = NULL
		 WHERE id = ?`,
		hash, id,
	)
	if err != nil {
		return fmt.Errorf("auth: admin set password: %w", err)
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

// AdminResetTOTP clears every TOTP-related column (including bumping the
// epoch so existing trusted-device cookies fail), deletes the user's
// recovery codes and trusted-device rows, and clears lockout counters.
// All in one transaction so partial failure can't leave a user with a
// TOTP secret but no recovery codes (or vice versa).
func (s *SQLiteAuthStore) AdminResetTOTP(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("auth: begin admin reset totp: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(
		`UPDATE users
		   SET totp_enabled = 0,
		       totp_secret = NULL, totp_secret_nonce = NULL, totp_secret_version = NULL,
		       totp_pending_secret = NULL, totp_pending_secret_nonce = NULL, totp_pending_secret_version = NULL,
		       totp_confirmed_at = NULL, totp_last_step = 0,
		       totp_epoch = totp_epoch + 1,
		       failed_attempts = 0,
		       locked_until = NULL
		 WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("auth: admin reset totp: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("auth: rows affected: %w", err)
	}
	if n == 0 {
		return ErrUserNotFound
	}
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, id); err != nil {
		return fmt.Errorf("auth: admin reset totp recovery: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM trusted_devices WHERE user_id = ?`, id); err != nil {
		return fmt.Errorf("auth: admin reset totp devices: %w", err)
	}
	return tx.Commit()
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

// SetPendingSecret stores an encrypted TOTP secret in `totp_pending_secret`
// plus its companion nonce and version columns. Always overwrites any prior
// pending secret — re-running enroll without confirming first is an explicit
// "throw away the old QR" action.
func (s *SQLiteAuthStore) SetPendingSecret(userID string, sealed Sealed) error {
	res, err := s.db.Exec(
		`UPDATE users SET totp_pending_secret = ?, totp_pending_secret_nonce = ?, totp_pending_secret_version = ? WHERE id = ?`,
		sealed.Ciphertext, sealed.Nonce, sealed.Version, userID,
	)
	if err != nil {
		return fmt.Errorf("auth: set pending totp: %w", err)
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

// ActivateTOTP promotes the pending secret to the active secret in a single
// transaction: copies pending→secret (including nonce + version), NULLs
// pending, sets enabled=1, stamps confirmed_at, resets last_step to 0.
// Recovery code insertion is left to the caller — that runs in the same
// handler but is a separate concern.
func (s *SQLiteAuthStore) ActivateTOTP(userID string, sealed Sealed, confirmedAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("auth: begin activate totp: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.activateTOTPIn(tx, userID, sealed, confirmedAt); err != nil {
		return err
	}
	return tx.Commit()
}

// ActivateTOTPTx is the in-transaction sibling: runs the same UPDATE
// inside the caller's tx so the audit row for `auth.totp.enroll` and
// the inserted recovery_codes rows commit alongside it. nil tx falls
// back to ActivateTOTP.
func (s *SQLiteAuthStore) ActivateTOTPTx(tx *sql.Tx, userID string, sealed Sealed, confirmedAt time.Time) error {
	if tx == nil {
		return s.ActivateTOTP(userID, sealed, confirmedAt)
	}
	return s.activateTOTPIn(tx, userID, sealed, confirmedAt)
}

func (s *SQLiteAuthStore) activateTOTPIn(tx *sql.Tx, userID string, sealed Sealed, confirmedAt time.Time) error {
	res, err := tx.Exec(
		`UPDATE users
		   SET totp_secret = ?, totp_secret_nonce = ?, totp_secret_version = ?,
		       totp_pending_secret = NULL, totp_pending_secret_nonce = NULL, totp_pending_secret_version = NULL,
		       totp_enabled = 1, totp_confirmed_at = ?, totp_last_step = 0
		 WHERE id = ?`,
		sealed.Ciphertext, sealed.Nonce, sealed.Version, confirmedAt.UnixNano(), userID,
	)
	if err != nil {
		return fmt.Errorf("auth: activate totp: %w", err)
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

// DisableTOTP undoes everything ActivateTOTP set up: bumps totp_epoch (so
// every existing trusted-device cookie is invalidated), clears the secret,
// turns enabled off, and deletes recovery codes plus trusted-device rows in
// the same transaction. The handler is expected to require password + code
// before calling this — DisableTOTP itself does no auth check.
func (s *SQLiteAuthStore) DisableTOTP(userID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("auth: begin disable totp: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.disableTOTPIn(tx, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// DisableTOTPTx is the in-transaction sibling: clears the same columns
// inside the caller's tx so the audit row for `auth.totp.disable`
// commits with the change. nil tx falls back to DisableTOTP.
func (s *SQLiteAuthStore) DisableTOTPTx(tx *sql.Tx, userID string) error {
	if tx == nil {
		return s.DisableTOTP(userID)
	}
	return s.disableTOTPIn(tx, userID)
}

func (s *SQLiteAuthStore) disableTOTPIn(tx *sql.Tx, userID string) error {
	res, err := tx.Exec(
		`UPDATE users
		   SET totp_enabled = 0,
		       totp_secret = NULL, totp_secret_nonce = NULL, totp_secret_version = NULL,
		       totp_pending_secret = NULL, totp_pending_secret_nonce = NULL, totp_pending_secret_version = NULL,
		       totp_confirmed_at = NULL, totp_last_step = 0,
		       totp_epoch = totp_epoch + 1
		 WHERE id = ?`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("auth: disable totp: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("auth: rows affected: %w", err)
	}
	if n == 0 {
		return ErrUserNotFound
	}
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("auth: delete recovery codes: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM trusted_devices WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("auth: delete trusted devices: %w", err)
	}
	return nil
}

// GetTOTPState returns every TOTP-related column for a single user in one
// query. Returns ErrUserNotFound if the user row is gone.
func (s *SQLiteAuthStore) GetTOTPState(userID string) (TOTPState, error) {
	var (
		enabled      int64
		secret       []byte
		secretNonce  []byte
		secretVer    sql.NullInt64
		pending      []byte
		pendingNonce []byte
		pendingVer   sql.NullInt64
		epoch        int64
		lastStep     int64
	)
	err := s.db.QueryRow(
		`SELECT totp_enabled,
		        totp_secret, totp_secret_nonce, totp_secret_version,
		        totp_pending_secret, totp_pending_secret_nonce, totp_pending_secret_version,
		        totp_epoch, totp_last_step
		   FROM users WHERE id = ?`,
		userID,
	).Scan(&enabled, &secret, &secretNonce, &secretVer,
		&pending, &pendingNonce, &pendingVer,
		&epoch, &lastStep)
	if errors.Is(err, sql.ErrNoRows) {
		return TOTPState{}, ErrUserNotFound
	}
	if err != nil {
		return TOTPState{}, fmt.Errorf("auth: load totp state: %w", err)
	}
	return TOTPState{
		Enabled:  enabled == 1,
		Secret:   Sealed{Ciphertext: secret, Nonce: secretNonce, Version: int(secretVer.Int64)},
		Pending:  Sealed{Ciphertext: pending, Nonce: pendingNonce, Version: int(pendingVer.Int64)},
		Epoch:    epoch,
		LastStep: lastStep,
	}, nil
}

// ConsumeStep atomically advances totp_last_step to step, but only if the
// stored value is strictly less than step. The "RowsAffected == 1" check is
// the linearisation point: a concurrent verify with the same code can only
// succeed once. ErrUnauthorized is returned on any miss (including a step
// already consumed) so the verify path treats them uniformly.
func (s *SQLiteAuthStore) ConsumeStep(userID string, step int64) error {
	res, err := s.db.Exec(
		`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`,
		step, userID, step,
	)
	if err != nil {
		return fmt.Errorf("auth: consume totp step: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("auth: rows affected: %w", err)
	}
	if n == 0 {
		return ErrUnauthorized
	}
	return nil
}

// InsertRecoveryCodes writes the bcrypt hashes of freshly-minted codes. It
// blanks any prior recovery codes for the user first so the user always has
// exactly RecoveryCodeCount unused codes after a confirm/regenerate call.
func (s *SQLiteAuthStore) InsertRecoveryCodes(userID string, hashes []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("auth: begin insert recovery: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.insertRecoveryCodesIn(tx, userID, hashes); err != nil {
		return err
	}
	return tx.Commit()
}

// InsertRecoveryCodesTx is the in-transaction sibling: shares the
// handler's tx so the recovery rows land alongside ActivateTOTPTx and
// its audit row. nil tx falls back to InsertRecoveryCodes.
func (s *SQLiteAuthStore) InsertRecoveryCodesTx(tx *sql.Tx, userID string, hashes []string) error {
	if tx == nil {
		return s.InsertRecoveryCodes(userID, hashes)
	}
	return s.insertRecoveryCodesIn(tx, userID, hashes)
}

func (s *SQLiteAuthStore) insertRecoveryCodesIn(tx *sql.Tx, userID string, hashes []string) error {
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("auth: clear recovery: %w", err)
	}
	for _, h := range hashes {
		if _, err := tx.Exec(
			`INSERT INTO recovery_codes (user_id, code_hash, used_at) VALUES (?, ?, NULL)`,
			userID, h,
		); err != nil {
			return fmt.Errorf("auth: insert recovery: %w", err)
		}
	}
	return nil
}

// ConsumeRecoveryCode iterates the user's unused codes, bcrypt-compares each
// against `presented`, and on a match marks that single row as used in an
// atomic UPDATE. The atomic update is the linearisation point — even if two
// requests race with the same code, only one will see RowsAffected==1.
func (s *SQLiteAuthStore) ConsumeRecoveryCode(userID, presented string, now time.Time) error {
	return s.consumeRecoveryCodeWith(nil, userID, presented, now)
}

// ConsumeRecoveryCodeTx is the in-transaction sibling so the verify
// path's audit row commits alongside the row update. nil tx falls back
// to the non-transactional ConsumeRecoveryCode.
func (s *SQLiteAuthStore) ConsumeRecoveryCodeTx(tx *sql.Tx, userID, presented string, now time.Time) error {
	if tx == nil {
		return s.ConsumeRecoveryCode(userID, presented, now)
	}
	return s.consumeRecoveryCodeWith(tx, userID, presented, now)
}

// recoveryRunner abstracts Query/Exec across *sql.DB and *sql.Tx so the
// recovery-code consumption logic isn't duplicated. Defined locally
// because the SELECT + UPDATE pair lives only in this method.
type recoveryRunner interface {
	Query(q string, args ...any) (*sql.Rows, error)
	Exec(q string, args ...any) (sql.Result, error)
}

func (s *SQLiteAuthStore) consumeRecoveryCodeWith(tx *sql.Tx, userID, presented string, now time.Time) error {
	var runner recoveryRunner = s.db
	if tx != nil {
		runner = tx
	}
	rows, err := runner.Query(
		`SELECT code_hash FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("auth: list recovery codes: %w", err)
	}
	hashes := []string{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			_ = rows.Close()
			return fmt.Errorf("auth: scan recovery code: %w", err)
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("auth: rows recovery: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("auth: close recovery rows: %w", err)
	}
	for _, h := range hashes {
		if err := CompareRecoveryCode(h, presented); err != nil {
			continue
		}
		res, err := runner.Exec(
			`UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
			now.UnixNano(), userID, h,
		)
		if err != nil {
			return fmt.Errorf("auth: mark recovery used: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("auth: rows affected: %w", err)
		}
		if n == 0 {
			// Lost a race with another request consuming this code.
			return ErrUnauthorized
		}
		return nil
	}
	return ErrUnauthorized
}

// DeleteRecoveryCodes clears all recovery codes for the user. Called by the
// handler in the same path as ActivateTOTP regenerates them, and indirectly
// by DisableTOTP via its inline DELETE.
func (s *SQLiteAuthStore) DeleteRecoveryCodes(userID string) error {
	if _, err := s.db.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("auth: delete recovery codes: %w", err)
	}
	return nil
}

// InsertDevice persists a trusted-device row. The cookie issued to the user
// references the row by id; we look it up on every login attempt.
func (s *SQLiteAuthStore) InsertDevice(d TrustedDevice) error {
	_, err := s.db.Exec(
		`INSERT INTO trusted_devices (id, user_id, label, created_at, last_used_at, expires_at, totp_epoch)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.UserID, d.Label,
		d.CreatedAt.UnixNano(), d.LastUsedAt.UnixNano(), d.ExpiresAt.UnixNano(),
		d.TOTPEpoch,
	)
	if err != nil {
		return fmt.Errorf("auth: insert device: %w", err)
	}
	return nil
}

// GetDevice returns a single trusted-device row by id. ErrUserNotFound is
// reused for "no such device" — it's the closest existing sentinel and the
// outer login flow treats both as "not trusted, fall back to TOTP".
func (s *SQLiteAuthStore) GetDevice(id string) (TrustedDevice, error) {
	var (
		d                                           TrustedDevice
		createdNs, lastUsedNs, expiresNs, totpEpoch int64
	)
	err := s.db.QueryRow(
		`SELECT id, user_id, label, created_at, last_used_at, expires_at, totp_epoch
		   FROM trusted_devices WHERE id = ?`,
		id,
	).Scan(&d.ID, &d.UserID, &d.Label, &createdNs, &lastUsedNs, &expiresNs, &totpEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		return TrustedDevice{}, ErrUserNotFound
	}
	if err != nil {
		return TrustedDevice{}, fmt.Errorf("auth: get device: %w", err)
	}
	d.CreatedAt = time.Unix(0, createdNs).UTC()
	d.LastUsedAt = time.Unix(0, lastUsedNs).UTC()
	d.ExpiresAt = time.Unix(0, expiresNs).UTC()
	d.TOTPEpoch = totpEpoch
	return d, nil
}

// ListDevices returns every trusted-device row for the user, including those
// that have technically expired — the UI surfaces both so users can revoke
// stale rows. The caller is responsible for filtering if needed.
func (s *SQLiteAuthStore) ListDevices(userID string) ([]TrustedDevice, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, label, created_at, last_used_at, expires_at, totp_epoch
		   FROM trusted_devices WHERE user_id = ? ORDER BY last_used_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: list devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []TrustedDevice{}
	for rows.Next() {
		var (
			d                                           TrustedDevice
			createdNs, lastUsedNs, expiresNs, totpEpoch int64
		)
		if err := rows.Scan(&d.ID, &d.UserID, &d.Label, &createdNs, &lastUsedNs, &expiresNs, &totpEpoch); err != nil {
			return nil, fmt.Errorf("auth: scan device: %w", err)
		}
		d.CreatedAt = time.Unix(0, createdNs).UTC()
		d.LastUsedAt = time.Unix(0, lastUsedNs).UTC()
		d.ExpiresAt = time.Unix(0, expiresNs).UTC()
		d.TOTPEpoch = totpEpoch
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: rows devices: %w", err)
	}
	return out, nil
}

// DeleteDevice removes a single trusted-device row. The user_id check makes
// the operation idempotent for the wrong owner — it returns ErrUserNotFound
// rather than 200, which is what the handler wants (404 on cross-user access).
func (s *SQLiteAuthStore) DeleteDevice(id, userID string) error {
	res, err := s.db.Exec(
		`DELETE FROM trusted_devices WHERE id = ? AND user_id = ?`,
		id, userID,
	)
	if err != nil {
		return fmt.Errorf("auth: delete device: %w", err)
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

// DeleteDevicesForUser clears every trusted-device row for the user. Called
// from DisableTOTP's transaction (inline) and from "sign out everywhere
// else" flows.
func (s *SQLiteAuthStore) DeleteDevicesForUser(userID string) error {
	if _, err := s.db.Exec(`DELETE FROM trusted_devices WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("auth: delete devices for user: %w", err)
	}
	return nil
}

// TouchDevice updates last_used_at on an existing row. Called every time a
// trusted-device cookie is honored at login so the UI shows fresh activity.
func (s *SQLiteAuthStore) TouchDevice(id string, lastUsed time.Time) error {
	res, err := s.db.Exec(
		`UPDATE trusted_devices SET last_used_at = ? WHERE id = ?`,
		lastUsed.UnixNano(), id,
	)
	if err != nil {
		return fmt.Errorf("auth: touch device: %w", err)
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

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(r rowScanner) (User, string, error) {
	var (
		u              User
		hash           string
		createdNs      int64
		totpEnabled    int64
		disabledNs     sql.NullInt64
		failedAttempts int64
		lockedUntilNs  sql.NullInt64
		mustChangePwd  int64
	)
	if err := r.Scan(&u.ID, &u.Username, &hash, &u.Email, &u.Theme, &createdNs, &totpEnabled, &disabledNs, &failedAttempts, &lockedUntilNs, &mustChangePwd); err != nil {
		return User{}, "", err
	}
	u.CreatedAt = time.Unix(0, createdNs).UTC()
	u.TotpEnabled = totpEnabled == 1
	if disabledNs.Valid {
		t := time.Unix(0, disabledNs.Int64).UTC()
		u.Disabled = true
		u.DisabledAt = &t
	}
	u.FailedAttempts = int(failedAttempts)
	if lockedUntilNs.Valid {
		t := time.Unix(0, lockedUntilNs.Int64).UTC()
		u.LockedUntil = &t
	}
	u.MustChangePassword = mustChangePwd == 1
	return u, hash, nil
}

// ListUsers returns all user rows ordered by creation time, oldest first.
// Both enabled and disabled users are included — the admin UI surfaces
// disabled rows so they can be reactivated.
func (s *SQLiteAuthStore) ListUsers() ([]User, error) {
	rows, err := s.db.Query(userSelect + ` ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("auth: list users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []User{}
	for rows.Next() {
		u, _, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("auth: scan user: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: list users rows: %w", err)
	}
	return out, nil
}

// Delete removes a user row along with every dependent row (trusted
// devices, recovery codes). Returns ErrUserNotFound when no user row
// matches id; the dependent deletes are best-effort cleanups and never
// produce a "not found" result on their own.
func (s *SQLiteAuthStore) Delete(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("auth: begin delete user: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("auth: delete user: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("auth: rows affected: %w", err)
	}
	if n == 0 {
		return ErrUserNotFound
	}
	if _, err := tx.Exec(`DELETE FROM trusted_devices WHERE user_id = ?`, id); err != nil {
		return fmt.Errorf("auth: delete user devices: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE user_id = ?`, id); err != nil {
		return fmt.Errorf("auth: delete user recovery: %w", err)
	}
	if s.PostDelete != nil {
		if err := s.PostDelete(tx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetDisabled flips a user's disabled_at column. disabled=true stamps now,
// disabled=false clears the column. Idempotent — disabling an already
// disabled user (or enabling an enabled one) succeeds and returns the
// current row. ErrUserNotFound when no row matches id.
func (s *SQLiteAuthStore) SetDisabled(id string, disabled bool, now time.Time) (User, error) {
	var (
		res sql.Result
		err error
	)
	if disabled {
		res, err = s.db.Exec(
			`UPDATE users SET disabled_at = ? WHERE id = ?`,
			now.UTC().UnixNano(), id,
		)
	} else {
		res, err = s.db.Exec(`UPDATE users SET disabled_at = NULL WHERE id = ?`, id)
	}
	if err != nil {
		return User{}, fmt.Errorf("auth: set disabled: %w", err)
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
