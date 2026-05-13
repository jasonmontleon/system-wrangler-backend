// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"log/slog"

	"system-wrangler-backend/internal/secrets"
)

// legacyTOTPKEKKey is the meta-table row that used to hold the in-DB
// key-encryption-key for TOTP secrets, predating the SW_MASTER_KEY_FILE
// scheme. MigrateLegacyTOTPSecrets reads it on first boot after rollout,
// re-encrypts every TOTP secret with the master key from the vault, and
// deletes the row so the in-DB key never sits next to the ciphertext again.
const legacyTOTPKEKKey = "totp_kek"

const legacyKEKSize = 32

// MigrateLegacyTOTPSecrets re-encrypts any TOTP secret rows still stored
// under the legacy in-DB KEK with the supplied vault, then deletes the
// legacy KEK from the meta table. The function is idempotent and a no-op
// against a fresh install (no legacy KEK present) or a database that has
// already been migrated.
//
// A row whose ciphertext is non-NULL but whose version is also non-NULL is
// assumed to be a successful prior migration and is left alone. A row whose
// ciphertext is NULL is skipped (no TOTP enrolled).
//
// Errors abort the migration in-flight; partial progress is committed (each
// row is its own transaction) so a retry converges. The caller is expected
// to log and exit non-zero on error — leaving the legacy KEK in place is
// safer than half-migrating.
func (s *SQLiteAuthStore) MigrateLegacyTOTPSecrets(v *secrets.Vault) error {
	kek, ok, err := s.LoadSecret(legacyTOTPKEKKey)
	if err != nil {
		return fmt.Errorf("auth: load legacy KEK: %w", err)
	}
	if !ok {
		return nil
	}
	if len(kek) != legacyKEKSize {
		return fmt.Errorf("auth: legacy KEK length = %d, want %d", len(kek), legacyKEKSize)
	}

	migrated, err := s.migrateLegacyColumn(v, kek,
		"totp_secret", "totp_secret_nonce", "totp_secret_version")
	if err != nil {
		return err
	}
	pendingMigrated, err := s.migrateLegacyColumn(v, kek,
		"totp_pending_secret", "totp_pending_secret_nonce", "totp_pending_secret_version")
	if err != nil {
		return err
	}

	if _, err := s.db.Exec(`DELETE FROM meta WHERE key = ?`, legacyTOTPKEKKey); err != nil {
		return fmt.Errorf("auth: delete legacy KEK: %w", err)
	}
	slog.Info("totp_legacy_kek_migrated",
		"rows_secret", migrated,
		"rows_pending", pendingMigrated,
		"new_version", v.CurrentVersion(),
	)
	return nil
}

// migrateLegacyColumn rewrites one (ciphertext, nonce, version) column
// triple. Returns the number of rows it re-sealed. Read the matching rows
// into a slice first so the UPDATE statements don't run against the same
// SELECT cursor — modernc.org/sqlite is single-conn, and a write while a
// SELECT is open against the same conn will block on itself.
func (s *SQLiteAuthStore) migrateLegacyColumn(v *secrets.Vault, kek []byte, ctCol, nonceCol, verCol string) (int, error) {
	work, err := s.scanLegacyRows(ctCol, verCol)
	if err != nil {
		return 0, err
	}
	// Column names are package-private constants supplied by the caller in
	// migrateLegacyTOTPSecrets — never user input, so the gosec SQL-format
	// warning is a false positive here.
	upd := fmt.Sprintf(`UPDATE users SET %s = ?, %s = ?, %s = ? WHERE id = ?`, ctCol, nonceCol, verCol) //nolint:gosec // G201
	for _, w := range work {
		plain, err := decryptLegacy(kek, w.legacy)
		if err != nil {
			return 0, fmt.Errorf("auth: decrypt legacy %s for %s: %w", ctCol, w.id, err)
		}
		sealed, err := SealWith(v, plain)
		if err != nil {
			return 0, fmt.Errorf("auth: re-seal %s for %s: %w", ctCol, w.id, err)
		}
		if _, err := s.db.Exec(upd, sealed.Ciphertext, sealed.Nonce, sealed.Version, w.id); err != nil {
			return 0, fmt.Errorf("auth: update legacy %s for %s: %w", ctCol, w.id, err)
		}
	}
	return len(work), nil
}

type legacyRow struct {
	id     string
	legacy []byte
}

// scanLegacyRows pulls the (id, ciphertext) of every row still on the
// legacy format for the given column pair. Split out so migrateLegacyColumn
// stays linear and the rows.Close() defer covers every exit path.
func (s *SQLiteAuthStore) scanLegacyRows(ctCol, verCol string) ([]legacyRow, error) {
	// Column names are package-private constants — see migrateLegacyColumn
	// for the analogous gosec G201 comment.
	q := fmt.Sprintf( //nolint:gosec // G201
		`SELECT id, %s FROM users WHERE %s IS NOT NULL AND %s IS NULL`,
		ctCol, ctCol, verCol,
	)
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("auth: scan legacy %s: %w", ctCol, err)
	}
	defer func() { _ = rows.Close() }()
	out := []legacyRow{}
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.id, &r.legacy); err != nil {
			return nil, fmt.Errorf("auth: scan legacy %s row: %w", ctCol, err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: rows legacy %s: %w", ctCol, err)
	}
	return out, nil
}

// decryptLegacy reverses the original Encrypt() format, which wrote
// `nonce || ciphertext || tag` as a single blob under a 32-byte AES-256
// key stored in the meta table. Kept inside this file because it has no
// callers outside the migration path.
func decryptLegacy(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("legacy ciphertext too short")
	}
	nonce, body := blob[:ns], blob[ns:]
	pt, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, ErrUnauthorized
	}
	return pt, nil
}

// encryptLegacyForTest is a tiny encrypt-with-legacy-KEK helper used only by
// the migration tests in this package. Kept private to the package so no
// production code can call it.
func encryptLegacyForTest(key, plaintext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("test nonce wrong size")
	}
	out := append([]byte(nil), nonce...)
	return gcm.Seal(out, nonce, plaintext, nil), nil
}
