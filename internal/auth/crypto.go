// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// TOTPKEKKey is the meta-table key under which the AES-256 key-encryption-key
// is stored. The KEK protects every TOTP shared secret at rest.
const TOTPKEKKey = "totp_kek"

// kekSize is the AES-256 key length in bytes.
const kekSize = 32

// LoadOrInitKEK returns the persisted 32-byte AES-256 key. On first call
// against a fresh DB it generates a key from crypto/rand and saves it.
// Mirrors LoadOrInitSecret in shape so the wiring path in main.go stays
// uniform.
func LoadOrInitKEK(s SecretStore) ([]byte, error) {
	val, ok, err := s.LoadSecret(TOTPKEKKey)
	if err != nil {
		return nil, err
	}
	if ok {
		if len(val) != kekSize {
			return nil, fmt.Errorf("auth: stored KEK length = %d, want %d", len(val), kekSize)
		}
		return val, nil
	}
	buf := make([]byte, kekSize)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("auth: generate KEK: %w", err)
	}
	if err := s.SaveSecret(TOTPKEKKey, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Encrypt seals plaintext under key using AES-256-GCM. The returned slice is
// `nonce || ciphertext || tag`; the GCM tag is appended by the cipher itself.
// Each call uses a fresh random 12-byte nonce, so the same plaintext encrypts
// to a different ciphertext each time — required for IND-CPA security under
// GCM and important here because the KEK is reused across many TOTP secrets.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != kekSize {
		return nil, fmt.Errorf("auth: encrypt key length = %d, want %d", len(key), kekSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: aes new: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: gcm new: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("auth: nonce: %w", err)
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+gcm.Overhead())
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. The first NonceSize bytes are the nonce; the rest
// is ciphertext-with-tag. ErrUnauthorized is returned on tag mismatch (a
// tampered ciphertext) so callers can collapse "tampered" and "wrong key"
// into a single uniform failure mode.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != kekSize {
		return nil, fmt.Errorf("auth: decrypt key length = %d, want %d", len(key), kekSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("auth: aes new: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("auth: gcm new: %w", err)
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("auth: ciphertext too short")
	}
	nonce, body := ciphertext[:ns], ciphertext[ns:]
	pt, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, ErrUnauthorized
	}
	return pt, nil
}
