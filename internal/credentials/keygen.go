// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// PublicKeyAuthorizedKeys returns priv's OpenSSH authorized_keys form,
// with a trailing newline trimmed so the column stores exactly one
// line. Used by both GenerateEd25519 (after keygen) and ParsePrivateKey
// (after user upload) so the on-disk format is always the same.
func publicKeyAuthorizedKeys(pub ssh.PublicKey) string {
	return strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")
}

// GenerateEd25519 produces a fresh ed25519 keypair. The private key
// is returned as an OpenSSH-format PEM block (the same shape
// `ssh-keygen -t ed25519` writes); the public key is returned in
// authorized_keys form so it can be pasted verbatim into a target
// host's ~/.ssh/authorized_keys.
//
// The PEM block has no passphrase — the caller seals it with the
// secrets vault before writing it to disk.
func GenerateEd25519() (publicKey string, privateKeyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("credentials: ed25519 keygen: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", nil, fmt.Errorf("credentials: marshal private: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("credentials: marshal public: %w", err)
	}
	return publicKeyAuthorizedKeys(sshPub), pem.EncodeToMemory(block), nil
}

// ParsePrivateKey accepts an operator-supplied SSH private key in
// either PEM form (`-----BEGIN OPENSSH PRIVATE KEY-----`, RSA legacy,
// ECDSA legacy) and returns its public key in authorized_keys form.
// The function is intentionally permissive about which algorithm
// the operator's existing fleet uses — per the design doc we trust
// what they paste so we don't break "we already have ansible
// working with key X" deployments.
//
// Encrypted (passphrase-protected) keys are rejected: SW would have
// to prompt for the passphrase on every connection, and the design
// doc commits to passwordless sudo on the v1 ergonomics floor —
// passphrase-on-key would land the same UX cliff.
func ParsePrivateKey(pemBytes []byte) (publicKey string, err error) {
	if len(pemBytes) == 0 {
		return "", errors.New("credentials: private key is empty")
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		// ssh.ParsePrivateKey wraps the inner error; detect the
		// encrypted-key case (which would otherwise reach the user
		// as "ssh: this private key is passphrase protected") and
		// surface a friendlier message.
		if strings.Contains(err.Error(), "passphrase") {
			return "", errors.New("credentials: passphrase-protected keys are not supported")
		}
		return "", fmt.Errorf("credentials: parse private key: %w", err)
	}
	return publicKeyAuthorizedKeys(signer.PublicKey()), nil
}
