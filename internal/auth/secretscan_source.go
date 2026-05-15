// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/secretscan"
)

// TOTPScanSource adapts SQLiteAuthStore.ListUndecryptableTOTP to the
// secretscan.Source interface. main.go composes it into the
// secretscan.Handler alongside future sources (ansible SSH keys,
// OIDC client secrets) without growing the auth package's HTTP
// surface.
type TOTPScanSource struct {
	Store *SQLiteAuthStore
}

// Name is the kind label the source emits in scan results. Matches the
// schema column family ("user_totp") so a future log search lines up
// with the audit-row target_kind for the same domain.
func (TOTPScanSource) Name() string { return "user_totp" }

// ListUndecryptable returns every (user, field) row whose sealed TOTP
// secret won't open under the supplied vault.
func (s TOTPScanSource) ListUndecryptable(v *secrets.Vault) ([]secretscan.Item, error) {
	rows, err := s.Store.ListUndecryptableTOTP(v)
	if err != nil {
		return nil, err
	}
	out := make([]secretscan.Item, 0, len(rows))
	for _, r := range rows {
		out = append(out, secretscan.Item{
			Kind:        s.Name(),
			Field:       string(r.Field),
			TargetID:    r.UserID,
			TargetLabel: r.Username,
			KeyVersion:  r.KeyVersion,
		})
	}
	return out, nil
}

// CountUndecryptable is the count-only fast path for badge UIs.
func (s TOTPScanSource) CountUndecryptable(v *secrets.Vault) (int, error) {
	return s.Store.CountUndecryptableTOTP(v)
}
