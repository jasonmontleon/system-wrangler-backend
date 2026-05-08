// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// RecoveryCodeCount is the number of one-time recovery codes generated when
// TOTP is confirmed. Ten is the de-facto standard (GitHub, Google) — enough
// for typical re-enrollment scenarios without becoming a maintenance burden.
const RecoveryCodeCount = 10

// recoveryCodeRawBytes controls the entropy per code. 8 bytes → 40 bits of
// entropy after base32 encoding, encoded as 13 unpadded chars; we strip the
// trailing 3 chars to keep the displayed length human-friendly while keeping
// 50 bits across what remains.
const recoveryCodeRawBytes = 8

// RecoveryCodeLength is the displayed length of each code (chars from
// crockford-style base32, hyphenated mid-string for readability).
const RecoveryCodeLength = 10

// GenerateRecoveryCodes returns n freshly-minted recovery codes. Each code is
// uppercase base32 (10 chars), formatted XXXXX-XXXXX for readability. They
// are returned in plaintext for one-time display to the user; the caller is
// responsible for hashing them before persistence and discarding the originals.
func GenerateRecoveryCodes(n int) ([]string, error) {
	if n <= 0 {
		return nil, fmt.Errorf("auth: recovery code count must be positive, got %d", n)
	}
	codes := make([]string, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, recoveryCodeRawBytes)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("auth: random for recovery code: %w", err)
		}
		raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
		raw = strings.ToUpper(raw)
		// Take the first RecoveryCodeLength chars, hyphenate at the midpoint.
		raw = raw[:RecoveryCodeLength]
		codes[i] = raw[:RecoveryCodeLength/2] + "-" + raw[RecoveryCodeLength/2:]
	}
	return codes, nil
}

// NormalizeRecoveryCode strips formatting (whitespace, hyphens) and uppercases
// the input so a user pasting a code with or without the dashes still verifies.
func NormalizeRecoveryCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// HashRecoveryCode bcrypts a normalized code. Uses the same default cost as
// password hashing — recovery codes have higher entropy than typical passwords,
// so default cost is appropriate.
func HashRecoveryCode(code string) (string, error) {
	normalized := NormalizeRecoveryCode(code)
	if normalized == "" {
		return "", fmt.Errorf("%w: empty recovery code", ErrInvalid)
	}
	b, err := bcrypt.GenerateFromPassword([]byte(normalized), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("auth: bcrypt recovery: %w", err)
	}
	return string(b), nil
}

// CompareRecoveryCode returns nil if the presented code matches the bcrypt
// hash, ErrUnauthorized otherwise. The presented code is normalized before
// the comparison.
func CompareRecoveryCode(hash, presented string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(NormalizeRecoveryCode(presented))); err != nil {
		return ErrUnauthorized
	}
	return nil
}
