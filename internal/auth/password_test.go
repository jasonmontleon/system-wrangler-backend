// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("hunter2hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
	if err := VerifyPassword(hash, "hunter2hunter2"); err != nil {
		t.Errorf("VerifyPassword on correct password: %v", err)
	}
	if err := VerifyPassword(hash, "wrong-password"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("VerifyPassword on wrong password: err = %v, want ErrUnauthorized", err)
	}
}

func TestHashPasswordTooShort(t *testing.T) {
	_, err := HashPassword("short")
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestVerifyPasswordMalformedHash(t *testing.T) {
	if err := VerifyPassword("not-a-bcrypt-hash", "password123"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}
