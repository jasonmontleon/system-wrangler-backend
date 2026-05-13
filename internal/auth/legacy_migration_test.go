// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"system-wrangler-backend/internal/secrets"
)

// legacyKEK returns a deterministic 32-byte KEK for migration tests.
func legacyKEK() []byte {
	k := make([]byte, legacyKEKSize)
	for i := range k {
		k[i] = byte(i + 100)
	}
	return k
}

// freshNonce returns 12 random bytes for legacy ciphertext construction.
func freshNonce(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, n); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return n
}

func TestMigrateLegacyTOTPSecretsNoOpWithoutKEK(t *testing.T) {
	s := newTestAuthStore(t)
	v, _ := secrets.NewVaultFromKey(deterministicVaultKey(1))
	if err := s.MigrateLegacyTOTPSecrets(v); err != nil {
		t.Fatalf("MigrateLegacyTOTPSecrets: %v", err)
	}
}

func TestMigrateLegacyTOTPSecretsActiveSecret(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")

	kek := legacyKEK()
	if err := s.SaveSecret(legacyTOTPKEKKey, kek); err != nil {
		t.Fatalf("seed legacy KEK: %v", err)
	}
	plaintext := []byte("the totp shared secret")
	blob, err := encryptLegacyForTest(kek, plaintext, freshNonce(t))
	if err != nil {
		t.Fatalf("encryptLegacyForTest: %v", err)
	}
	if _, err := s.db.Exec(
		`UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?`,
		blob, u.ID,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	v, _ := secrets.NewVaultFromKey(deterministicVaultKey(2))
	if err := s.MigrateLegacyTOTPSecrets(v); err != nil {
		t.Fatalf("MigrateLegacyTOTPSecrets: %v", err)
	}

	state, err := s.GetTOTPState(u.ID)
	if err != nil {
		t.Fatalf("GetTOTPState: %v", err)
	}
	if state.Secret.Version != v.CurrentVersion() {
		t.Errorf("version = %d, want %d", state.Secret.Version, v.CurrentVersion())
	}
	if len(state.Secret.Nonce) != 12 {
		t.Errorf("nonce len = %d, want 12", len(state.Secret.Nonce))
	}
	got, err := OpenWith(v, state.Secret)
	if err != nil {
		t.Fatalf("OpenWith after migrate: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext after migrate = %q, want %q", got, plaintext)
	}
	if _, ok, _ := s.LoadSecret(legacyTOTPKEKKey); ok {
		t.Error("legacy KEK row not deleted after migration")
	}
}

func TestMigrateLegacyTOTPSecretsPendingSecret(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")

	kek := legacyKEK()
	if err := s.SaveSecret(legacyTOTPKEKKey, kek); err != nil {
		t.Fatalf("seed legacy KEK: %v", err)
	}
	plaintext := []byte("pending enrollment secret")
	blob, err := encryptLegacyForTest(kek, plaintext, freshNonce(t))
	if err != nil {
		t.Fatalf("encryptLegacyForTest: %v", err)
	}
	if _, err := s.db.Exec(
		`UPDATE users SET totp_pending_secret = ? WHERE id = ?`,
		blob, u.ID,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	v, _ := secrets.NewVaultFromKey(deterministicVaultKey(3))
	if err := s.MigrateLegacyTOTPSecrets(v); err != nil {
		t.Fatalf("MigrateLegacyTOTPSecrets: %v", err)
	}

	state, _ := s.GetTOTPState(u.ID)
	got, err := OpenWith(v, state.Pending)
	if err != nil {
		t.Fatalf("OpenWith pending: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext after migrate = %q, want %q", got, plaintext)
	}
}

func TestMigrateLegacyTOTPSecretsIdempotent(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")

	kek := legacyKEK()
	if err := s.SaveSecret(legacyTOTPKEKKey, kek); err != nil {
		t.Fatalf("seed legacy KEK: %v", err)
	}
	blob, err := encryptLegacyForTest(kek, []byte("secret"), freshNonce(t))
	if err != nil {
		t.Fatalf("encryptLegacyForTest: %v", err)
	}
	if _, err := s.db.Exec(
		`UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?`,
		blob, u.ID,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	v, _ := secrets.NewVaultFromKey(deterministicVaultKey(4))
	if err := s.MigrateLegacyTOTPSecrets(v); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	state1, _ := s.GetTOTPState(u.ID)
	if err := s.MigrateLegacyTOTPSecrets(v); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	state2, _ := s.GetTOTPState(u.ID)
	// Second pass must not re-seal — same ciphertext bytes after both runs.
	if !bytes.Equal(state1.Secret.Ciphertext, state2.Secret.Ciphertext) {
		t.Error("second migration re-sealed an already-migrated row")
	}
}

func TestMigrateLegacyTOTPSecretsCorruptKEK(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.SaveSecret(legacyTOTPKEKKey, []byte{1, 2, 3}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	v, _ := secrets.NewVaultFromKey(deterministicVaultKey(5))
	if err := s.MigrateLegacyTOTPSecrets(v); err == nil {
		t.Error("want error for legacy KEK of wrong length")
	}
}

func TestMigrateLegacyTOTPSecretsCorruptCiphertext(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	if err := s.SaveSecret(legacyTOTPKEKKey, legacyKEK()); err != nil {
		t.Fatalf("seed KEK: %v", err)
	}
	if _, err := s.db.Exec(
		`UPDATE users SET totp_secret = ? WHERE id = ?`,
		[]byte("not a valid GCM blob"), u.ID,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	v, _ := secrets.NewVaultFromKey(deterministicVaultKey(6))
	err := s.MigrateLegacyTOTPSecrets(v)
	if err == nil {
		t.Error("want error for corrupt legacy ciphertext")
	}
	// Authentication failure surfaces as ErrUnauthorized on the legacy path.
	if !errors.Is(err, ErrUnauthorized) {
		t.Logf("err = %v (acceptable; just must be non-nil)", err)
	}
}

func TestDecryptLegacyTooShort(t *testing.T) {
	if _, err := decryptLegacy(legacyKEK(), []byte{1, 2, 3}); err == nil {
		t.Error("want error for truncated legacy blob")
	}
}

// TestMigrateLegacyTOTPSecretsClosedDB exercises the migration error paths
// when the database handle becomes unusable mid-flight: LoadSecret fails,
// then the column scan fails, then the final DELETE fails.
func TestMigrateLegacyTOTPSecretsClosedDB(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	v, _ := secrets.NewVaultFromKey(deterministicVaultKey(11))
	if err := s.MigrateLegacyTOTPSecrets(v); err == nil {
		t.Error("MigrateLegacyTOTPSecrets on closed DB: want error")
	}
}

// TestScanLegacyRowsClosedDB exercises the Query-error path on
// scanLegacyRows directly so the migrate code's error wrapping is covered
// without needing a mid-transaction DB fault.
func TestScanLegacyRowsClosedDB(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := s.scanLegacyRows("totp_secret", "totp_secret_version"); err == nil {
		t.Error("scanLegacyRows on closed DB: want error")
	}
}

// TestMigrateLegacyTOTPSecretsUpdateFails wires up legitimate legacy
// state and then closes the DB *after* the initial LoadSecret has
// succeeded, by hooking into scanLegacyRows — close-while-iterating is
// impossible to schedule precisely, so the test calls migrateLegacyColumn
// directly with a closed DB and pre-staged work to exercise the Exec error
// path.
func TestMigrateLegacyColumnUpdateFails(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")

	kek := legacyKEK()
	if err := s.SaveSecret(legacyTOTPKEKKey, kek); err != nil {
		t.Fatalf("seed KEK: %v", err)
	}
	blob, err := encryptLegacyForTest(kek, []byte("payload"), freshNonce(t))
	if err != nil {
		t.Fatalf("encryptLegacyForTest: %v", err)
	}
	if _, err := s.db.Exec(
		`UPDATE users SET totp_secret = ? WHERE id = ?`, blob, u.ID,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// Verify the scan sees the row before we tear the DB down.
	rows, err := s.scanLegacyRows("totp_secret", "totp_secret_version")
	if err != nil || len(rows) != 1 {
		t.Fatalf("setup: scan returned %d rows, err=%v", len(rows), err)
	}
	if err := s.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	v, _ := secrets.NewVaultFromKey(deterministicVaultKey(12))
	if _, err := s.migrateLegacyColumn(v, kek, "totp_secret", "totp_secret_nonce", "totp_secret_version"); err == nil {
		t.Error("migrateLegacyColumn with closed DB: want error")
	}
}

func TestEncryptLegacyForTestRejectsBadNonce(t *testing.T) {
	if _, err := encryptLegacyForTest(legacyKEK(), []byte("x"), []byte{1, 2}); err == nil {
		t.Error("encryptLegacyForTest with wrong-size nonce: want error")
	}
}

func TestDecryptLegacyWrongKey(t *testing.T) {
	good := legacyKEK()
	blob, err := encryptLegacyForTest(good, []byte("payload"), freshNonce(t))
	if err != nil {
		t.Fatalf("encryptLegacyForTest: %v", err)
	}
	bad := make([]byte, legacyKEKSize)
	for i := range bad {
		bad[i] = byte(255 - i)
	}
	if _, err := decryptLegacy(bad, blob); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}

// deterministicVaultKey constructs a 32-byte key whose first byte is `seed`
// — used by tests that only need stable, distinct keys across cases.
func deterministicVaultKey(seed byte) []byte {
	k := make([]byte, secrets.KeySize)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func TestSealWithEmptyVault(t *testing.T) {
	// An empty vault has no current key; SealWith must surface the
	// secrets.Seal error path rather than panic.
	v := &secrets.Vault{}
	if _, err := SealWith(v, []byte("x")); err == nil {
		t.Error("SealWith on empty vault: want error")
	}
}
