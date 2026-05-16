// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateEd25519RoundTrip(t *testing.T) {
	pub, priv, err := GenerateEd25519()
	if err != nil {
		t.Fatalf("GenerateEd25519: %v", err)
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Errorf("public key missing ssh-ed25519 prefix: %q", pub)
	}
	if strings.HasSuffix(pub, "\n") {
		t.Error("public key has trailing newline; want trimmed")
	}
	// Parse the freshly-generated private and confirm we recover
	// the same public-key line. End-to-end roundtrip.
	got, err := ParsePrivateKey(priv)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if got != pub {
		t.Errorf("roundtrip pubkey mismatch:\n  generated: %s\n  parsed:    %s", pub, got)
	}
}

func TestParsePrivateKeyEmpty(t *testing.T) {
	if _, err := ParsePrivateKey(nil); err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestParsePrivateKeyRejectsGarbage(t *testing.T) {
	if _, err := ParsePrivateKey([]byte("not a key")); err == nil {
		t.Fatal("expected error for garbage input")
	}
}

func TestParsePrivateKeyAcceptsRSA(t *testing.T) {
	// User-supplied path must accept a non-ed25519 key — operators
	// with existing fleets paste whatever already works.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	pub, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey RSA: %v", err)
	}
	if !strings.HasPrefix(pub, "ssh-rsa ") {
		t.Errorf("RSA public key has unexpected prefix: %q", pub)
	}
}

func TestParsePrivateKeyRejectsEncrypted(t *testing.T) {
	// Encrypt an ed25519 key with x509 EncryptPEMBlock equivalent
	// — easier: build a fake passphrase-protected OpenSSH PEM by
	// hand. Easier still: ssh.MarshalPrivateKeyWithPassphrase. Use
	// the real API.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("secret"))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	_, err = ParsePrivateKey(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("expected error for passphrase-protected key")
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("error %q does not mention passphrase", err.Error())
	}
}
