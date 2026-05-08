// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"errors"
	"testing"
)

func newTestKEK(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, kekSize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := newTestKEK(t)
	plain := []byte("a TOTP shared secret")
	ct, err := Encrypt(key, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ct, plain) {
		t.Error("ciphertext leaks plaintext bytes")
	}
	got, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("got %q, want %q", got, plain)
	}
}

func TestEncryptProducesDistinctCiphertexts(t *testing.T) {
	// GCM nonce uniqueness: encrypting the same plaintext twice must yield
	// distinct ciphertexts. If this flakes we have a serious bug.
	key := newTestKEK(t)
	plain := []byte("same input")
	a, _ := Encrypt(key, plain)
	b, _ := Encrypt(key, plain)
	if bytes.Equal(a, b) {
		t.Error("two encryptions of same plaintext are identical (nonce reuse?)")
	}
}

func TestDecryptRejectsTampered(t *testing.T) {
	key := newTestKEK(t)
	ct, _ := Encrypt(key, []byte("payload"))
	ct[len(ct)-1] ^= 0x01
	if _, err := Decrypt(key, ct); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	key := newTestKEK(t)
	other := make([]byte, kekSize)
	for i := range other {
		other[i] = byte(255 - i)
	}
	ct, _ := Encrypt(key, []byte("payload"))
	if _, err := Decrypt(other, ct); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}

func TestDecryptRejectsTooShort(t *testing.T) {
	key := newTestKEK(t)
	if _, err := Decrypt(key, []byte{1, 2, 3}); err == nil {
		t.Error("decrypt of truncated input: want error")
	}
}

func TestEncryptRejectsBadKeyLength(t *testing.T) {
	if _, err := Encrypt(make([]byte, 16), []byte("x")); err == nil {
		t.Error("encrypt with 16-byte key: want error")
	}
}

func TestDecryptRejectsBadKeyLength(t *testing.T) {
	if _, err := Decrypt(make([]byte, 16), make([]byte, 32)); err == nil {
		t.Error("decrypt with 16-byte key: want error")
	}
}

func TestLoadOrInitKEKFirstCallGenerates(t *testing.T) {
	s := &stubSecretStore{}
	got, err := LoadOrInitKEK(s)
	if err != nil {
		t.Fatalf("LoadOrInitKEK: %v", err)
	}
	if len(got) != kekSize {
		t.Errorf("len = %d, want %d", len(got), kekSize)
	}
	stored, ok, _ := s.LoadSecret(TOTPKEKKey)
	if !ok || !bytes.Equal(stored, got) {
		t.Errorf("KEK not persisted: stored=%v got=%v", stored, got)
	}
}

func TestLoadOrInitKEKSecondCallReturnsSame(t *testing.T) {
	s := &stubSecretStore{}
	first, _ := LoadOrInitKEK(s)
	second, err := LoadOrInitKEK(s)
	if err != nil {
		t.Fatalf("second LoadOrInitKEK: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("KEK regenerated on second call")
	}
}

func TestLoadOrInitKEKRejectsCorruptedStoredKey(t *testing.T) {
	s := &stubSecretStore{}
	if err := s.SaveSecret(TOTPKEKKey, []byte{1, 2, 3}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := LoadOrInitKEK(s); err == nil {
		t.Error("want error for short stored KEK")
	}
}

func TestLoadOrInitKEKLoadError(t *testing.T) {
	bad := errors.New("boom")
	s := &stubSecretStore{failOn: "load", err: bad}
	if _, err := LoadOrInitKEK(s); !errors.Is(err, bad) {
		t.Errorf("err = %v, want %v", err, bad)
	}
}

func TestLoadOrInitKEKSaveError(t *testing.T) {
	bad := errors.New("boom")
	s := &stubSecretStore{failOn: "save", err: bad}
	if _, err := LoadOrInitKEK(s); !errors.Is(err, bad) {
		t.Errorf("err = %v, want %v", err, bad)
	}
}
