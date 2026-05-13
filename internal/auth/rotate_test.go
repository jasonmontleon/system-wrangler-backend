// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"system-wrangler-backend/internal/secrets"
)

// sealUnderKey is a test helper: build a single-key vault, seal `plain`,
// and return the resulting Sealed plus the vault's version. Lets tests
// stage rows under arbitrary "old" keys to exercise rotation.
func sealUnderKey(t *testing.T, keySeed byte, plain []byte) (Sealed, int) {
	t.Helper()
	v, err := secrets.NewVaultFromKey(deterministicVaultKey(keySeed))
	if err != nil {
		t.Fatalf("NewVaultFromKey: %v", err)
	}
	s, err := SealWith(v, plain)
	if err != nil {
		t.Fatalf("SealWith: %v", err)
	}
	return s, v.CurrentVersion()
}

func TestRotateKeysNoWork(t *testing.T) {
	// Fresh DB, no enrolled users → rotate succeeds with zero rotations.
	s := newTestAuthStore(t)
	v, _ := secrets.NewVaultFromKey(deterministicVaultKey(50))
	r, err := s.RotateKeys(v)
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	if r.SecretRotated != 0 || r.PendingRotated != 0 {
		t.Errorf("rotated something on empty DB: %+v", r)
	}
	if r.NewVersion != v.CurrentVersion() {
		t.Errorf("NewVersion = %d, want %d", r.NewVersion, v.CurrentVersion())
	}
}

func TestRotateKeysReSealsActiveSecret(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")

	plain := []byte("alice's totp secret")
	oldSealed, _ := sealUnderKey(t, 60, plain)
	if err := s.ActivateTOTP(u.ID, oldSealed, time.Now()); err != nil {
		t.Fatalf("ActivateTOTP: %v", err)
	}

	// Build a two-key vault: current = new, previous = old. The vault has
	// to know the old version to decrypt the existing row.
	prev := deterministicVaultKey(60)
	cur := deterministicVaultKey(61)
	curVault, _ := secrets.NewVaultFromKey(cur)
	if err := loadPrevKeyForTest(curVault, prev); err != nil {
		t.Fatalf("load previous: %v", err)
	}

	r, err := s.RotateKeys(curVault)
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	if r.SecretRotated != 1 {
		t.Errorf("SecretRotated = %d, want 1", r.SecretRotated)
	}

	state, _ := s.GetTOTPState(u.ID)
	if state.Secret.Version != curVault.CurrentVersion() {
		t.Errorf("version after rotate = %d, want %d", state.Secret.Version, curVault.CurrentVersion())
	}
	got, err := OpenWith(curVault, state.Secret)
	if err != nil {
		t.Fatalf("OpenWith after rotate: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("plaintext after rotate = %q, want %q", got, plain)
	}
}

func TestRotateKeysReSealsPendingSecret(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")

	plain := []byte("pending enrollment secret")
	oldSealed, _ := sealUnderKey(t, 70, plain)
	if err := s.SetPendingSecret(u.ID, oldSealed); err != nil {
		t.Fatalf("SetPendingSecret: %v", err)
	}

	prev := deterministicVaultKey(70)
	cur := deterministicVaultKey(71)
	curVault, _ := secrets.NewVaultFromKey(cur)
	if err := loadPrevKeyForTest(curVault, prev); err != nil {
		t.Fatalf("load previous: %v", err)
	}
	r, err := s.RotateKeys(curVault)
	if err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	if r.PendingRotated != 1 {
		t.Errorf("PendingRotated = %d, want 1", r.PendingRotated)
	}
	state, _ := s.GetTOTPState(u.ID)
	got, err := OpenWith(curVault, state.Pending)
	if err != nil {
		t.Fatalf("OpenWith pending after rotate: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("plaintext after rotate = %q, want %q", got, plain)
	}
}

func TestRotateKeysIdempotent(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")

	oldSealed, _ := sealUnderKey(t, 80, []byte("secret"))
	if err := s.ActivateTOTP(u.ID, oldSealed, time.Now()); err != nil {
		t.Fatalf("ActivateTOTP: %v", err)
	}
	prev := deterministicVaultKey(80)
	cur := deterministicVaultKey(81)
	curVault, _ := secrets.NewVaultFromKey(cur)
	_ = loadPrevKeyForTest(curVault, prev)

	if _, err := s.RotateKeys(curVault); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	r2, err := s.RotateKeys(curVault)
	if err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	if r2.SecretRotated != 0 {
		t.Errorf("second-pass SecretRotated = %d, want 0", r2.SecretRotated)
	}
	if r2.SecretAlready != 1 {
		t.Errorf("second-pass SecretAlready = %d, want 1", r2.SecretAlready)
	}
}

func TestRotateKeysUnknownVersionIsHardError(t *testing.T) {
	// Operator drops the previous key before rotation — a row whose
	// version isn't loaded must surface as an error, never silently
	// rewritten or skipped.
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	oldSealed, _ := sealUnderKey(t, 90, []byte("secret"))
	if err := s.ActivateTOTP(u.ID, oldSealed, time.Now()); err != nil {
		t.Fatalf("ActivateTOTP: %v", err)
	}

	// Vault with only the new key — the old version is not loaded.
	curVault, _ := secrets.NewVaultFromKey(deterministicVaultKey(91))
	_, err := s.RotateKeys(curVault)
	if err == nil {
		t.Fatal("want error for row whose version is unknown to the vault")
	}
	if !strings.Contains(err.Error(), "not loaded") {
		t.Errorf("err = %v, want it to mention 'not loaded'", err)
	}
	// State must not have been rewritten.
	state, _ := s.GetTOTPState(u.ID)
	if state.Secret.Version != oldSealed.Version {
		t.Errorf("version after failed rotate = %d, want preserved %d", state.Secret.Version, oldSealed.Version)
	}
}

func TestRotateKeysNilVault(t *testing.T) {
	s := newTestAuthStore(t)
	if _, err := s.RotateKeys(nil); err == nil {
		t.Error("RotateKeys with nil vault: want error")
	}
}

func TestRotateKeysClosedDB(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	v, _ := secrets.NewVaultFromKey(deterministicVaultKey(95))
	if _, err := s.RotateKeys(v); err == nil {
		t.Error("RotateKeys on closed DB: want error")
	}
}

// loadPrevKeyForTest writes prev to a temp file and calls LoadPrevious so
// the test exercises the same code path the operator does. Returns an
// error rather than t.Fatal so callers can assert against it explicitly.
func loadPrevKeyForTest(v *secrets.Vault, prev []byte) error {
	other, err := secrets.NewVaultFromKey(prev)
	if err != nil {
		return err
	}
	if other.CurrentVersion() == v.CurrentVersion() {
		return errors.New("test setup: prev key matches current")
	}
	dir, err := os.MkdirTemp("", "sw-test-prev-*")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "prev.key")
	encoded := base64.StdEncoding.EncodeToString(prev)
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		return err
	}
	return v.LoadPrevious(path)
}
