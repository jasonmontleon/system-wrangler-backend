// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func deterministicKey(seed byte) []byte {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	v, err := NewVaultFromKey(deterministicKey(1))
	if err != nil {
		t.Fatalf("NewVaultFromKey: %v", err)
	}
	plain := []byte("a TOTP shared secret")
	ct, nonce, ver, err := v.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(ct, plain) {
		t.Error("ciphertext leaks plaintext bytes")
	}
	if ver != v.CurrentVersion() {
		t.Errorf("Seal returned version %d, want current %d", ver, v.CurrentVersion())
	}
	got, err := v.Open(ct, nonce, ver)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("got %q, want %q", got, plain)
	}
}

func TestSealProducesDistinctCiphertexts(t *testing.T) {
	v, _ := NewVaultFromKey(deterministicKey(2))
	plain := []byte("same input")
	a, _, _, _ := v.Seal(plain)
	b, _, _, _ := v.Seal(plain)
	if bytes.Equal(a, b) {
		t.Error("two seals of same plaintext are identical (nonce reuse?)")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	v, _ := NewVaultFromKey(deterministicKey(3))
	ct, nonce, ver, _ := v.Seal([]byte("payload"))
	ct[len(ct)-1] ^= 0x01
	if _, err := v.Open(ct, nonce, ver); !errors.Is(err, ErrDecrypt) {
		t.Errorf("err = %v, want ErrDecrypt", err)
	}
}

func TestOpenRejectsTamperedNonce(t *testing.T) {
	v, _ := NewVaultFromKey(deterministicKey(4))
	ct, nonce, ver, _ := v.Seal([]byte("payload"))
	nonce[0] ^= 0xFF
	if _, err := v.Open(ct, nonce, ver); !errors.Is(err, ErrDecrypt) {
		t.Errorf("err = %v, want ErrDecrypt", err)
	}
}

func TestOpenRejectsWrongLengthNonce(t *testing.T) {
	v, _ := NewVaultFromKey(deterministicKey(5))
	ct, _, ver, _ := v.Seal([]byte("payload"))
	if _, err := v.Open(ct, []byte{1, 2, 3}, ver); !errors.Is(err, ErrDecrypt) {
		t.Errorf("err = %v, want ErrDecrypt", err)
	}
}

func TestOpenWithUnknownVersion(t *testing.T) {
	v, _ := NewVaultFromKey(deterministicKey(6))
	ct, nonce, ver, _ := v.Seal([]byte("payload"))
	if _, err := v.Open(ct, nonce, ver+1); !errors.Is(err, ErrUnknownVersion) {
		t.Errorf("err = %v, want ErrUnknownVersion", err)
	}
}

func TestNewVaultFromKeyRejectsBadLength(t *testing.T) {
	if _, err := NewVaultFromKey(make([]byte, 16)); err == nil {
		t.Error("want error for 16-byte key")
	}
}

func TestVersionIsDeterministic(t *testing.T) {
	a, _ := NewVaultFromKey(deterministicKey(7))
	b, _ := NewVaultFromKey(deterministicKey(7))
	if a.CurrentVersion() != b.CurrentVersion() {
		t.Errorf("same key produced versions %d and %d", a.CurrentVersion(), b.CurrentVersion())
	}
}

func TestDifferentKeysGetDifferentVersions(t *testing.T) {
	a, _ := NewVaultFromKey(deterministicKey(8))
	b, _ := NewVaultFromKey(deterministicKey(9))
	if a.CurrentVersion() == b.CurrentVersion() {
		t.Errorf("two keys collided on version %d (1-in-2^32 fluke or bug?)", a.CurrentVersion())
	}
}

// writeKeyFile is a test helper: writes 32 random-looking bytes (the seed
// shape) as base64 to a temp file and returns the path.
func writeKeyFile(t *testing.T, seed byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	encoded := base64.StdEncoding.EncodeToString(deterministicKey(seed))
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestNewVaultReadsCurrentKey(t *testing.T) {
	path := writeKeyFile(t, 10)
	t.Setenv(EnvKeyFile, path)
	t.Setenv(EnvKeyFilePrevious, "")
	v, err := NewVault()
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	if v.CurrentVersion() == 0 {
		t.Error("version 0 looks unset")
	}
	if got := v.Versions(); len(got) != 1 {
		t.Errorf("versions = %v, want one", got)
	}
}

func TestNewVaultMissingEnv(t *testing.T) {
	t.Setenv(EnvKeyFile, "")
	if _, err := NewVault(); err == nil {
		t.Error("want error when env unset")
	}
}

func TestNewVaultMissingFile(t *testing.T) {
	t.Setenv(EnvKeyFile, filepath.Join(t.TempDir(), "missing"))
	if _, err := NewVault(); err == nil {
		t.Error("want error when file missing")
	}
}

func TestNewVaultEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(EnvKeyFile, path)
	if _, err := NewVault(); err == nil {
		t.Error("want error for whitespace-only file")
	}
}

func TestNewVaultBadBase64(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk")
	if err := os.WriteFile(path, []byte("!!!not base64!!!"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(EnvKeyFile, path)
	if _, err := NewVault(); err == nil {
		t.Error("want error for non-base64 content")
	}
}

func TestNewVaultWrongKeyLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short")
	encoded := base64.StdEncoding.EncodeToString([]byte("only twenty bytes long"))
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(EnvKeyFile, path)
	if _, err := NewVault(); err == nil {
		t.Error("want error when decoded key is not 32 bytes")
	}
}

func TestNewVaultLoadsPrevious(t *testing.T) {
	cur := writeKeyFile(t, 20)
	prev := writeKeyFile(t, 21)
	t.Setenv(EnvKeyFile, cur)
	t.Setenv(EnvKeyFilePrevious, prev)
	v, err := NewVault()
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	if got := v.Versions(); len(got) != 2 {
		t.Errorf("versions = %v, want two", got)
	}
	// Seal/Open round-trip uses the current key.
	ct, nonce, ver, err := v.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if ver != v.CurrentVersion() {
		t.Errorf("seal version %d, want current %d", ver, v.CurrentVersion())
	}
	if _, err := v.Open(ct, nonce, ver); err != nil {
		t.Errorf("Open with current: %v", err)
	}
}

func TestNewVaultPreviousMatchesCurrentRejected(t *testing.T) {
	// Pointing both env vars at the same key has no rotation benefit and is
	// almost certainly an operator mistake. Surface it loudly.
	path := writeKeyFile(t, 30)
	t.Setenv(EnvKeyFile, path)
	t.Setenv(EnvKeyFilePrevious, path)
	if _, err := NewVault(); err == nil {
		t.Error("want error when previous = current")
	}
}

func TestNewVaultPreviousMissingFile(t *testing.T) {
	path := writeKeyFile(t, 31)
	t.Setenv(EnvKeyFile, path)
	t.Setenv(EnvKeyFilePrevious, filepath.Join(t.TempDir(), "nope"))
	if _, err := NewVault(); err == nil {
		t.Error("want error when previous file missing")
	}
}

func TestDropVersion(t *testing.T) {
	cur := writeKeyFile(t, 40)
	prev := writeKeyFile(t, 41)
	t.Setenv(EnvKeyFile, cur)
	t.Setenv(EnvKeyFilePrevious, prev)
	v, _ := NewVault()
	versions := v.Versions()
	var prevVer int
	for _, x := range versions {
		if x != v.CurrentVersion() {
			prevVer = x
		}
	}
	v.DropVersion(prevVer)
	if len(v.Versions()) != 1 {
		t.Errorf("versions after drop = %v, want one", v.Versions())
	}
	// Dropping current is a no-op so an Open against fresh ciphertext still
	// works after the call.
	v.DropVersion(v.CurrentVersion())
	if len(v.Versions()) != 1 {
		t.Errorf("drop-current changed vault: %v", v.Versions())
	}
}

func TestSealOnEmptyVault(t *testing.T) {
	v := &Vault{keys: map[int][]byte{}, current: 0}
	if _, _, _, err := v.Seal([]byte("x")); err == nil {
		t.Error("Seal on empty vault: want error")
	}
}

func TestFatalMessageMentionsEnvVar(t *testing.T) {
	if msg := FatalMessage(); !bytes.Contains([]byte(msg), []byte(EnvKeyFile)) {
		t.Error("fatal message does not mention SW_MASTER_KEY_FILE")
	}
}
