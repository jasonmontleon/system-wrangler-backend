// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"database/sql"
	"errors"
	"fmt"

	"system-wrangler-backend/internal/secrets"
)

// TOTPField names which encrypted column on `users` could not be
// decrypted with the currently-loaded vault.
type TOTPField string

// Sealed columns inspected by the scan. `secret` is the confirmed
// authenticator; `pending` is an enrollment-in-progress secret that
// hasn't been promoted yet. Both are visible to the operator so the
// banner can drive remediation regardless of which row is stuck.
const (
	TOTPFieldSecret  TOTPField = "secret"
	TOTPFieldPending TOTPField = "pending"
)

// UndecryptableTOTP is one row in the scan result. KeyVersion is the
// version the row was originally sealed under (i.e. the version not
// loaded in the current vault, or the version whose key bytes
// changed). Username is a frozen snapshot for the banner — the
// caller doesn't need to re-look it up to render the affected list.
type UndecryptableTOTP struct {
	UserID     string
	Username   string
	Field      TOTPField
	KeyVersion int
}

// CountUndecryptableTOTP returns just the count of affected rows.
// Used by the lightweight "is anything broken" badge so the UI
// doesn't pay for the full list when it only needs to decide
// whether to render the banner.
func (s *SQLiteAuthStore) CountUndecryptableTOTP(v *secrets.Vault) (int, error) {
	if v == nil {
		return 0, errors.New("auth: undecryptable scan: vault is nil")
	}
	rows, err := s.scanSealedTOTPColumns()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rows {
		if _, err := v.Open(r.ct, r.nonce, r.version); err != nil {
			if secrets.IsUnrecoverable(err) {
				n++
				continue
			}
			return 0, fmt.Errorf("auth: undecryptable scan (user %s field %s): %w", r.userID, r.field, err)
		}
	}
	return n, nil
}

// ListUndecryptableTOTP returns every row whose sealed TOTP secret
// (either the active `secret` or an `pending` enrollment) fails to
// decrypt under the supplied vault. Returned in (username, field)
// order so the UI can render a stable, deduplicated list.
func (s *SQLiteAuthStore) ListUndecryptableTOTP(v *secrets.Vault) ([]UndecryptableTOTP, error) {
	if v == nil {
		return nil, errors.New("auth: undecryptable scan: vault is nil")
	}
	rows, err := s.scanSealedTOTPColumns()
	if err != nil {
		return nil, err
	}
	out := []UndecryptableTOTP{}
	for _, r := range rows {
		if _, err := v.Open(r.ct, r.nonce, r.version); err != nil {
			if secrets.IsUnrecoverable(err) {
				out = append(out, UndecryptableTOTP{
					UserID:     r.userID,
					Username:   r.username,
					Field:      r.field,
					KeyVersion: r.version,
				})
				continue
			}
			return nil, fmt.Errorf("auth: undecryptable scan (user %s field %s): %w", r.userID, r.field, err)
		}
	}
	return out, nil
}

// sealedTOTPRow is the internal projection of one (user, field)
// sealed-column triple read out of the users table.
type sealedTOTPRow struct {
	userID   string
	username string
	field    TOTPField
	ct       []byte
	nonce    []byte
	version  int
}

// scanSealedTOTPColumns reads every non-NULL TOTP sealed triple from
// the users table, projecting both columns (`secret` and `pending`)
// as separate rows. Sorted by (username, field) so callers can rely
// on a stable order without re-sorting.
func (s *SQLiteAuthStore) scanSealedTOTPColumns() ([]sealedTOTPRow, error) {
	rows, err := s.db.Query(`
		SELECT id, username,
		       totp_secret, totp_secret_nonce, totp_secret_version,
		       totp_pending_secret, totp_pending_secret_nonce, totp_pending_secret_version
		  FROM users
		 ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("auth: scan sealed totp: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []sealedTOTPRow
	for rows.Next() {
		var (
			id, username string
			secret       []byte
			secretNonce  []byte
			secretVer    sql.NullInt64
			pending      []byte
			pendingNonce []byte
			pendingVer   sql.NullInt64
		)
		if err := rows.Scan(&id, &username,
			&secret, &secretNonce, &secretVer,
			&pending, &pendingNonce, &pendingVer); err != nil {
			return nil, fmt.Errorf("auth: scan row: %w", err)
		}
		if len(secret) > 0 && secretVer.Valid {
			out = append(out, sealedTOTPRow{
				userID: id, username: username, field: TOTPFieldSecret,
				ct: secret, nonce: secretNonce, version: int(secretVer.Int64),
			})
		}
		if len(pending) > 0 && pendingVer.Valid {
			out = append(out, sealedTOTPRow{
				userID: id, username: username, field: TOTPFieldPending,
				ct: pending, nonce: pendingNonce, version: int(pendingVer.Int64),
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: scan rows: %w", err)
	}
	return out, nil
}
