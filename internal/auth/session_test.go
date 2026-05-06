// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func TestSignAndVerifySessionRoundTrip(t *testing.T) {
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	tok, err := SignSession(testSecret, "user-1", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	uid, err := VerifySession(testSecret, now, tok)
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if uid != "user-1" {
		t.Errorf("uid = %q, want %q", uid, "user-1")
	}
}

func TestVerifySessionExpired(t *testing.T) {
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	tok, err := SignSession(testSecret, "user-1", now.Add(-time.Second))
	if err != nil {
		t.Fatalf("SignSession: %v", err)
	}
	if _, err := VerifySession(testSecret, now, tok); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}

func TestVerifySessionTampered(t *testing.T) {
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	tok, _ := SignSession(testSecret, "user-1", now.Add(time.Hour))
	// flip the last char of the signature
	mutated := tok[:len(tok)-1] + "X"
	if _, err := VerifySession(testSecret, now, mutated); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("tampered err = %v, want ErrUnauthorized", err)
	}
}

func TestVerifySessionWrongSecret(t *testing.T) {
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	tok, _ := SignSession(testSecret, "user-1", now.Add(time.Hour))
	other := []byte("different-secret-32-chars-long-aa")
	if _, err := VerifySession(other, now, tok); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("wrong secret err = %v, want ErrUnauthorized", err)
	}
}

func TestVerifySessionMalformed(t *testing.T) {
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	tests := []string{
		"",
		"no-dot",
		"!!!.!!!",
		"validlooking.notbase64!@#",
	}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			if _, err := VerifySession(testSecret, now, tt); !errors.Is(err, ErrUnauthorized) {
				t.Errorf("err = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestSignSessionEmptySecret(t *testing.T) {
	if _, err := SignSession(nil, "u", time.Now()); err == nil {
		t.Error("want error for empty secret")
	}
}

func TestVerifySessionEmptySecret(t *testing.T) {
	if _, err := VerifySession(nil, time.Now(), "x.y"); err == nil {
		t.Error("want error for empty secret")
	}
}

// stubSecretStore lets us exercise LoadOrInitSecret without SQLite.
type stubSecretStore struct {
	values map[string][]byte
	failOn string
	err    error
}

func (s *stubSecretStore) LoadSecret(key string) ([]byte, bool, error) {
	if s.failOn == "load" {
		return nil, false, s.err
	}
	v, ok := s.values[key]
	return v, ok, nil
}

func (s *stubSecretStore) SaveSecret(key string, val []byte) error {
	if s.failOn == "save" {
		return s.err
	}
	if s.values == nil {
		s.values = map[string][]byte{}
	}
	s.values[key] = val
	return nil
}

func TestLoadOrInitSecretFirstCallGenerates(t *testing.T) {
	s := &stubSecretStore{}
	got, err := LoadOrInitSecret(s)
	if err != nil {
		t.Fatalf("LoadOrInitSecret: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("len = %d, want 32", len(got))
	}
	// Persisted under the well-known key.
	stored, ok, _ := s.LoadSecret(SessionSecretKey)
	if !ok || string(stored) != string(got) {
		t.Errorf("secret not persisted: stored=%q got=%q", stored, got)
	}
}

func TestLoadOrInitSecretSecondCallReturnsSame(t *testing.T) {
	s := &stubSecretStore{}
	first, _ := LoadOrInitSecret(s)
	second, err := LoadOrInitSecret(s)
	if err != nil {
		t.Fatalf("second LoadOrInitSecret: %v", err)
	}
	if string(first) != string(second) {
		t.Error("secret regenerated on second call")
	}
}

func TestLoadOrInitSecretLoadError(t *testing.T) {
	bad := errors.New("boom")
	s := &stubSecretStore{failOn: "load", err: bad}
	if _, err := LoadOrInitSecret(s); !errors.Is(err, bad) {
		t.Errorf("err = %v, want %v", err, bad)
	}
}

func TestLoadOrInitSecretSaveError(t *testing.T) {
	bad := errors.New("boom")
	s := &stubSecretStore{failOn: "save", err: bad}
	if _, err := LoadOrInitSecret(s); !errors.Is(err, bad) {
		t.Errorf("err = %v, want %v", err, bad)
	}
}
