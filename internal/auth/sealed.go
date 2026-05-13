// SPDX-License-Identifier: Apache-2.0

package auth

import "system-wrangler-backend/internal/secrets"

// Sealed bundles the three values written to disk for every encrypted
// secret: the AES-256-GCM ciphertext (which includes the auth tag), the
// 12-byte nonce, and the integer version of the key the ciphertext was
// sealed under. Storing the nonce and version next to the ciphertext lets
// us run with multiple loaded keys during rotation without re-encrypting
// every row at once.
type Sealed struct {
	Ciphertext []byte
	Nonce      []byte
	Version    int
}

// IsZero reports whether s holds no ciphertext. Convenient for handlers
// that need to distinguish "user has a pending secret" from "user has not
// started enrollment yet" without checking three fields by hand.
func (s Sealed) IsZero() bool {
	return len(s.Ciphertext) == 0
}

// SealWith encrypts plaintext through vault and returns the Sealed triple.
// Centralised here so handlers don't repeat the three-value-to-struct dance.
func SealWith(v *secrets.Vault, plaintext []byte) (Sealed, error) {
	ct, nonce, ver, err := v.Seal(plaintext)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{Ciphertext: ct, Nonce: nonce, Version: ver}, nil
}

// OpenWith is the inverse of SealWith.
func OpenWith(v *secrets.Vault, s Sealed) ([]byte, error) {
	return v.Open(s.Ciphertext, s.Nonce, s.Version)
}
