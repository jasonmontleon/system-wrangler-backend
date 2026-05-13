// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"fmt"
	"log/slog"

	"system-wrangler-backend/internal/secrets"
)

// RotateResult is the per-call summary RotateKeys returns. The columns
// each carry their own count so a partially-converted database (e.g. an
// active secret re-sealed but a pending one still on the old version)
// shows up clearly in the operator-facing log line.
type RotateResult struct {
	NewVersion     int
	SecretRotated  int
	PendingRotated int
	SecretAlready  int
	PendingAlready int
}

// RotateKeys re-seals every TOTP secret currently encrypted under a key
// that is not vault.CurrentVersion(). Idempotent — a row already on the
// current version is skipped, so retries after a partial run converge.
//
// A row whose version is unknown to the vault (neither current nor a
// loaded previous key) is a hard error: the operator dropped a key too
// early. The error surfaces; the row is not silently rewritten or
// deleted.
//
// Intended to be called once at boot when both SW_MASTER_KEY_FILE and
// SW_MASTER_KEY_FILE_PREVIOUS are set, from a one-shot `-rotate-keys`
// invocation of the server binary. Not exposed as an HTTP endpoint in v1.
func (s *SQLiteAuthStore) RotateKeys(v *secrets.Vault) (RotateResult, error) {
	if v == nil {
		return RotateResult{}, errors.New("auth: rotate requires a vault")
	}
	secRot, secSkip, err := s.rotateColumn(v,
		"totp_secret", "totp_secret_nonce", "totp_secret_version")
	if err != nil {
		return RotateResult{}, err
	}
	pendRot, pendSkip, err := s.rotateColumn(v,
		"totp_pending_secret", "totp_pending_secret_nonce", "totp_pending_secret_version")
	if err != nil {
		return RotateResult{}, err
	}
	r := RotateResult{
		NewVersion:     v.CurrentVersion(),
		SecretRotated:  secRot,
		PendingRotated: pendRot,
		SecretAlready:  secSkip,
		PendingAlready: pendSkip,
	}
	slog.Info("totp_keys_rotated",
		"new_version", r.NewVersion,
		"secret_rotated", r.SecretRotated,
		"pending_rotated", r.PendingRotated,
		"secret_already_current", r.SecretAlready,
		"pending_already_current", r.PendingAlready,
	)
	return r, nil
}

// rotateColumn rewrites a single column triple. Returns (rotated, skipped).
// The skipped count is how many rows were already on the current version —
// useful as an idempotency assertion in the operator-facing log.
func (s *SQLiteAuthStore) rotateColumn(v *secrets.Vault, ctCol, nonceCol, verCol string) (int, int, error) {
	work, skipped, err := s.scanRotatable(v.CurrentVersion(), ctCol, nonceCol, verCol)
	if err != nil {
		return 0, 0, err
	}
	// Column names are package-private constants supplied by the caller —
	// the gosec SQL-format warning is a false positive.
	upd := fmt.Sprintf(`UPDATE users SET %s = ?, %s = ?, %s = ? WHERE id = ?`, //nolint:gosec // G201
		ctCol, nonceCol, verCol)
	for _, w := range work {
		plain, err := v.Open(w.ct, w.nonce, w.ver)
		if err != nil {
			if errors.Is(err, secrets.ErrUnknownVersion) {
				return 0, 0, fmt.Errorf("auth: rotate %s for %s: row encrypted under version %d which is not loaded — operator must set SW_MASTER_KEY_FILE_PREVIOUS to that key before rotating",
					ctCol, w.id, w.ver)
			}
			return 0, 0, fmt.Errorf("auth: open %s for %s: %w", ctCol, w.id, err)
		}
		sealed, err := SealWith(v, plain)
		if err != nil {
			return 0, 0, fmt.Errorf("auth: re-seal %s for %s: %w", ctCol, w.id, err)
		}
		if _, err := s.db.Exec(upd, sealed.Ciphertext, sealed.Nonce, sealed.Version, w.id); err != nil {
			return 0, 0, fmt.Errorf("auth: update %s for %s: %w", ctCol, w.id, err)
		}
	}
	return len(work), skipped, nil
}

type rotateRow struct {
	id    string
	ct    []byte
	nonce []byte
	ver   int
}

// scanRotatable pulls (id, ciphertext, nonce, version) for every row whose
// version is non-NULL — the migration step has converted NULL versions to
// the new shape, so any remaining NULL means "this user never enrolled in
// TOTP" and is correctly skipped. Returns work split into "needs rotate"
// and the count of "already on current".
func (s *SQLiteAuthStore) scanRotatable(currentVer int, ctCol, nonceCol, verCol string) ([]rotateRow, int, error) {
	// Same false-positive: column names are package-private constants.
	q := fmt.Sprintf( //nolint:gosec // G201
		`SELECT id, %s, %s, %s FROM users WHERE %s IS NOT NULL`,
		ctCol, nonceCol, verCol, verCol,
	)
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, 0, fmt.Errorf("auth: scan %s for rotate: %w", ctCol, err)
	}
	defer func() { _ = rows.Close() }()
	var (
		work    []rotateRow
		skipped int
	)
	for rows.Next() {
		var r rotateRow
		if err := rows.Scan(&r.id, &r.ct, &r.nonce, &r.ver); err != nil {
			return nil, 0, fmt.Errorf("auth: scan %s row: %w", ctCol, err)
		}
		if r.ver == currentVer {
			skipped++
			continue
		}
		work = append(work, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("auth: rows %s: %w", ctCol, err)
	}
	return work, skipped, nil
}
