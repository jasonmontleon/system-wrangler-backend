// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword applies bcrypt at the default cost (10). A length floor is
// enforced here so the policy is in one place.
func HashPassword(plaintext string) (string, error) {
	if len(plaintext) < MinPasswordLen {
		return "", fmt.Errorf("%w: password must be at least %d characters", ErrInvalid, MinPasswordLen)
	}
	b, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("auth: bcrypt: %w", err)
	}
	return string(b), nil
}

// VerifyPassword returns nil if plaintext matches hash, ErrUnauthorized
// otherwise. We deliberately collapse "wrong password" and "malformed hash"
// into the same error so callers can't accidentally leak which one happened.
func VerifyPassword(hash, plaintext string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)); err != nil {
		return ErrUnauthorized
	}
	return nil
}
