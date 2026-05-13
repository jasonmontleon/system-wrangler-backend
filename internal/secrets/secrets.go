// SPDX-License-Identifier: Apache-2.0

// Package secrets is the single boundary every handler crosses to encrypt or
// decrypt sensitive data at rest. The master key is read from
// SW_MASTER_KEY_FILE; AES-256-GCM is the only algorithm; each ciphertext row
// is stored as a (ciphertext, nonce, version) triple so the operator can
// rotate keys without rewriting every column at once.
//
// The package is deliberately small. Callers cannot choose algorithm or
// nonce; the version is opaque metadata they shuttle between Seal and Open.
// No crypto/cipher import is needed anywhere else in the codebase.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// KeySize is the AES-256 key length in bytes. Exported so callers building a
// vault from raw bytes (tests, future rotation tooling) can assert the size.
const KeySize = 32

// EnvKeyFile is the env var pointing at the active master key file.
const EnvKeyFile = "SW_MASTER_KEY_FILE"

// EnvKeyFilePrevious is the env var pointing at the outgoing key file during
// a rotation. Optional; when unset the vault holds exactly one key.
const EnvKeyFilePrevious = "SW_MASTER_KEY_FILE_PREVIOUS"

// ErrUnknownVersion is returned by Open when the supplied version isn't
// loaded in the vault. The caller should surface "this row was encrypted
// with a key you no longer have" — silently dropping the row is wrong.
var ErrUnknownVersion = errors.New("secrets: ciphertext version is not loaded in this vault")

// ErrDecrypt collapses every authentication failure (tampered ciphertext,
// wrong key, truncated input) into a single sentinel so callers don't need
// to distinguish between them.
var ErrDecrypt = errors.New("secrets: decrypt failed")

// Vault holds one or more loaded master keys, indexed by a version derived
// deterministically from the key bytes. At steady state a Vault holds
// exactly one key; during a rotation it briefly holds the outgoing key
// alongside the incoming one.
type Vault struct {
	keys    map[int][]byte
	current int
}

// NewVaultFromKey builds a single-key vault from raw 32-byte key material.
// Used by tests and by NewVault after it has read the key from disk. The
// returned vault's current version is derived from the key bytes — same
// key, same version across boots and across hosts.
func NewVaultFromKey(key []byte) (*Vault, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secrets: key length = %d, want %d", len(key), KeySize)
	}
	v := versionOf(key)
	cp := append([]byte(nil), key...)
	return &Vault{keys: map[int][]byte{v: cp}, current: v}, nil
}

// NewVault reads SW_MASTER_KEY_FILE (and the optional
// SW_MASTER_KEY_FILE_PREVIOUS) and returns a Vault. The returned error is
// suitable for the "container exits with explanation" path: callers should
// print FatalMessage and exit non-zero on any failure.
func NewVault() (*Vault, error) {
	path := os.Getenv(EnvKeyFile)
	if path == "" {
		return nil, fmt.Errorf("secrets: %s is not set", EnvKeyFile)
	}
	key, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	v, err := NewVaultFromKey(key)
	if err != nil {
		return nil, err
	}
	if prev := os.Getenv(EnvKeyFilePrevious); prev != "" {
		if err := v.LoadPrevious(prev); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// LoadPrevious adds a second key to the vault for rotation. Reads from the
// same on-disk shape as SW_MASTER_KEY_FILE. The previous key keeps its
// derived version; current is unchanged.
func (v *Vault) LoadPrevious(path string) error {
	key, err := readKeyFile(path)
	if err != nil {
		return err
	}
	ver := versionOf(key)
	if ver == v.current {
		return errors.New("secrets: previous key matches current key (rotation is a no-op)")
	}
	v.keys[ver] = append([]byte(nil), key...)
	return nil
}

// DropVersion retires a loaded key. After rotation completes the operator
// runs this for the outgoing version so a stale row written between
// re-seal and restart can't decrypt against an old key the vault should
// no longer honor.
func (v *Vault) DropVersion(version int) {
	if version == v.current {
		return
	}
	delete(v.keys, version)
}

// CurrentVersion reports which version Seal will tag new ciphertext with.
// Exposed so tests and admin tooling can assert which key is active without
// reaching into the package internals.
func (v *Vault) CurrentVersion() int {
	return v.current
}

// Versions returns the versions currently loaded. Useful for boot-time
// logging and rotation tooling. Order is unspecified.
func (v *Vault) Versions() []int {
	out := make([]int, 0, len(v.keys))
	for k := range v.keys {
		out = append(out, k)
	}
	return out
}

// Seal encrypts plaintext with the current key. The three returned values
// map directly onto the three storage columns (ciphertext, nonce, version).
// A fresh 12-byte nonce is drawn from crypto/rand on every call; reuse
// against the same key is statistically negligible at our write volume.
func (v *Vault) Seal(plaintext []byte) (ciphertext, nonce []byte, version int, err error) {
	key, ok := v.keys[v.current]
	if !ok {
		return nil, nil, 0, errors.New("secrets: vault is empty")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, 0, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, 0, fmt.Errorf("secrets: nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, v.current, nil
}

// Open decrypts using whichever loaded key matches version. Returns
// ErrUnknownVersion if version isn't loaded (the caller should treat that
// as "row encrypted with a key you no longer have") and ErrDecrypt for any
// authentication failure (tampered ciphertext, wrong key, truncated input).
func (v *Vault) Open(ciphertext, nonce []byte, version int) ([]byte, error) {
	key, ok := v.keys[version]
	if !ok {
		return nil, ErrUnknownVersion
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	pt, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcm: %w", err)
	}
	return gcm, nil
}

// versionOf derives a deterministic 32-bit version tag from the key bytes.
// Same key → same version across every boot; two different keys collide
// only on a 1-in-2^32 birthday, which is irrelevant at one-key-per-install
// scale. Storing the tag rather than a sequence number means we don't need
// to persist a "next version" counter to the database.
func versionOf(key []byte) int {
	sum := sha256.Sum256(key)
	return int(binary.BigEndian.Uint32(sum[:4]))
}

// readKeyFile decodes the base64-encoded 32-byte key at path. Surrounding
// whitespace (newlines, trailing spaces) is tolerated — operators routinely
// leave a trailing \n from `head -c 32 /dev/urandom | base64 > key` and
// rejecting that would be hostile for no benefit.
func readKeyFile(path string) ([]byte, error) {
	// The path comes from the operator via SW_MASTER_KEY_FILE; reading it
	// is the whole point of the function. gosec's variable-path warning is
	// a false positive here.
	raw, err := os.ReadFile(path) //nolint:gosec // G304
	if err != nil {
		return nil, fmt.Errorf("secrets: read %s: %w", path, err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("secrets: key file %s is empty", path)
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("secrets: decode %s: %w", path, err)
	}
	if len(decoded) != KeySize {
		return nil, fmt.Errorf("secrets: key in %s decodes to %d bytes, want %d", path, len(decoded), KeySize)
	}
	return decoded, nil
}

// FatalMessage returns the operator-facing block printed when NewVault
// fails. Kept as one string constant so the wording stays consistent across
// startup, docs, and tests.
func FatalMessage() string {
	return `fatal: encryption-at-rest master key is required.

Generate a 32-byte key, restrict its permissions, and set
SW_MASTER_KEY_FILE to its path:

    head -c 32 /dev/urandom | base64 > /path/to/master.key
    chmod 600 /path/to/master.key
    export SW_MASTER_KEY_FILE=/path/to/master.key

This file is the operator's responsibility. Back it up. Store it
separately from your database backups. If you lose it, every
encrypted secret in the database (TOTP, ansible SSH keys, OIDC
secrets, alert credentials) becomes permanently unrecoverable.
System Wrangler does not store, mirror, or escrow this key.`
}
