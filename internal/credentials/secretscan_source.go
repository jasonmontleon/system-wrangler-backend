// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"errors"

	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/secretscan"
)

// ScanSource adapts the credentials store to the secretscan.Source
// interface. main.go composes it alongside auth.TOTPScanSource so a
// mismatched-key restore surfaces ansible private keys on the same
// admin banner that already covers TOTP secrets. The implementation
// walks Store.List once per call and tries each slot's sealed
// column against the vault.
type ScanSource struct {
	Store Store
}

// Name is the kind label the source emits in scan results. Matches
// the schema column family ("ansible_credential") so future log
// search lines up with the audit-row target_kind.
func (ScanSource) Name() string { return "ansible_credential" }

// ListUndecryptable returns every slot whose sealed private key
// won't open under v. Slots with no key column set (user-only slots)
// are skipped — there's nothing to decrypt.
func (s ScanSource) ListUndecryptable(v *secrets.Vault) ([]secretscan.Item, error) {
	if v == nil {
		return nil, errors.New("credentials: undecryptable scan: vault is nil")
	}
	slots, err := s.Store.List()
	if err != nil {
		return nil, err
	}
	out := []secretscan.Item{}
	for _, slot := range slots {
		if slot.PrivateKey.IsZero() {
			continue
		}
		if _, err := v.Open(slot.PrivateKey.Ciphertext, slot.PrivateKey.Nonce, slot.PrivateKey.Version); err != nil {
			if !secrets.IsUnrecoverable(err) {
				return nil, err
			}
			out = append(out, secretscan.Item{
				Kind:        s.Name(),
				Field:       "private_key",
				TargetID:    slot.ID,
				TargetLabel: labelFor(slot),
				KeyVersion:  slot.PrivateKey.Version,
			})
		}
	}
	return out, nil
}

// CountUndecryptable is the count-only fast path for badge UIs.
func (s ScanSource) CountUndecryptable(v *secrets.Vault) (int, error) {
	items, err := s.ListUndecryptable(v)
	if err != nil {
		return 0, err
	}
	return len(items), nil
}

// labelFor renders a human-readable identifier for a slot. The
// underlying scope_id is opaque (group or system UUID) so we lean
// on the scope kind to give the operator a place to start looking.
func labelFor(s Slot) string {
	switch s.ScopeKind {
	case ScopeGlobal:
		return "global default"
	case ScopeGroup:
		return "group " + s.ScopeID
	case ScopeSystem:
		return "system " + s.ScopeID
	}
	return string(s.ScopeKind)
}
