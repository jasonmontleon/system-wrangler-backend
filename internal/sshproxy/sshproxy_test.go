// SPDX-License-Identifier: Apache-2.0

package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"system-wrangler-backend/internal/credentials"
	"system-wrangler-backend/internal/hostkeys"
	"system-wrangler-backend/internal/systems"
)

// TestAcceptedKeysCallbackPasses verifies the callback admits a key
// whose (algorithm, fingerprint) is on the accepted list.
func TestAcceptedKeysCallbackPasses(t *testing.T) {
	pub := generateTestKey(t)
	accepted := []hostkeys.HostKey{
		{Algorithm: pub.Type(), Fingerprint: ssh.FingerprintSHA256(pub)},
	}
	cb := acceptedKeysCallback(accepted)
	if err := cb("h", &net.TCPAddr{}, pub); err != nil {
		t.Errorf("matching key rejected: %v", err)
	}
}

// TestAcceptedKeysCallbackRejects verifies the callback refuses a key
// whose fingerprint isn't on the accepted list.
func TestAcceptedKeysCallbackRejects(t *testing.T) {
	pub := generateTestKey(t)
	other := generateTestKey(t)
	accepted := []hostkeys.HostKey{
		{Algorithm: other.Type(), Fingerprint: ssh.FingerprintSHA256(other)},
	}
	cb := acceptedKeysCallback(accepted)
	err := cb("h", &net.TCPAddr{}, pub)
	if err == nil || !errors.Is(err, ErrHostKeyMatch) {
		t.Errorf("mismatch err = %v, want ErrHostKeyMatch", err)
	}
}

// TestAcceptedKeysCallbackAlgoSensitive verifies the algorithm string
// is part of the match key.
func TestAcceptedKeysCallbackAlgoSensitive(t *testing.T) {
	pub := generateTestKey(t)
	// Same fingerprint, wrong algo string.
	accepted := []hostkeys.HostKey{
		{Algorithm: "ssh-rsa", Fingerprint: ssh.FingerprintSHA256(pub)},
	}
	cb := acceptedKeysCallback(accepted)
	err := cb("h", &net.TCPAddr{}, pub)
	if err == nil {
		t.Error("expected algorithm mismatch to fail")
	}
}

// Cancellation behavior of dialThroughClient requires a real *ssh.Client to
// exercise the goroutine path safely (the zero-value Client panics on Dial).
// That kind of end-to-end test belongs against a fixture SSH server which
// is out of scope for unit tests. The select-based cancellation is
// straightforward to read, and the panic-on-zero behavior is a Go SSH
// library implementation detail.
var _ = context.Background // keep the context import used

func TestProxyDefaults(t *testing.T) {
	p := &Proxy{}
	if p.dialTimeout() <= 0 {
		t.Errorf("dialTimeout = %v, want positive", p.dialTimeout())
	}
	if p.fetchTimeout() <= 0 {
		t.Errorf("fetchTimeout = %v, want positive", p.fetchTimeout())
	}
	if p.sshPort() != 22 {
		t.Errorf("sshPort = %d, want 22", p.sshPort())
	}
}

type stubSystems struct {
	sys systems.System
	err error
}

func (s stubSystems) Get(string) (systems.System, error) {
	return s.sys, s.err
}

func (s stubSystems) List() ([]systems.System, error) { return nil, nil }
func (s stubSystems) Create(systems.SystemInput) (systems.System, error) {
	return systems.System{}, nil
}
func (s stubSystems) CreateTx(*sql.Tx, systems.SystemInput) (systems.System, error) {
	return systems.System{}, nil
}
func (s stubSystems) Delete(string) error            { return nil }
func (s stubSystems) DeleteTx(*sql.Tx, string) error { return nil }
func (s stubSystems) UpdateProbe(string, bool, time.Time, int, int) (bool, error) {
	return false, nil
}
func (s stubSystems) SetGroup(string, *string) error                       { return nil }
func (s stubSystems) ClearGroup(string) error                              { return nil }
func (s stubSystems) SetPlatform(string, bool) error                       { return nil }
func (s stubSystems) SetPlatformTx(*sql.Tx, string, bool) error            { return nil }
func (s stubSystems) SetPlatformInfo(string, string, string, string) error { return nil }
func (s stubSystems) SetRebootRequired(string, time.Time) error            { return nil }
func (s stubSystems) ClearRebootRequired(string) error                     { return nil }

type stubCreds struct {
	slot credentials.Slot
	err  error
}

func (s stubCreds) GetByScope(credentials.ScopeKind, string) (credentials.Slot, error) {
	return s.slot, s.err
}
func (s stubCreds) Upsert(credentials.Slot) (credentials.Slot, error) {
	return credentials.Slot{}, nil
}
func (s stubCreds) Delete(credentials.ScopeKind, string) error { return nil }
func (s stubCreds) List() ([]credentials.Slot, error)          { return nil, nil }

func TestFetchOverTunnelLookupSystemError(t *testing.T) {
	p := &Proxy{Systems: stubSystems{err: errors.New("db down")}}
	_, err := p.FetchOverTunnel(context.Background(), "x", "127.0.0.1", 9100, "/metrics")
	if err == nil || !errContains(err, "lookup system") {
		t.Errorf("err = %v, want lookup wrap", err)
	}
}

func TestFetchOverTunnelNoCredentials(t *testing.T) {
	p := &Proxy{
		Systems:     stubSystems{sys: systems.System{ID: "x"}},
		Credentials: stubCreds{err: credentials.ErrNotFound},
	}
	_, err := p.FetchOverTunnel(context.Background(), "x", "127.0.0.1", 9100, "/metrics")
	if !errors.Is(err, ErrNoCredentials) {
		t.Errorf("err = %v, want ErrNoCredentials", err)
	}
}

func TestFetchOverTunnelCredentialsResolveError(t *testing.T) {
	p := &Proxy{
		Systems:     stubSystems{sys: systems.System{ID: "x"}},
		Credentials: stubCreds{err: errors.New("scopes down")},
	}
	_, err := p.FetchOverTunnel(context.Background(), "x", "127.0.0.1", 9100, "/metrics")
	if err == nil || !errContains(err, "resolve credentials") {
		t.Errorf("err = %v, want resolve credentials wrap", err)
	}
}

func errContains(err error, substr string) bool {
	return err != nil && strings.Contains(err.Error(), substr)
}

func TestIsTimeout(t *testing.T) {
	if isTimeout(nil) {
		t.Error("nil should not be a timeout")
	}
	if isTimeout(errors.New("nope")) {
		t.Error("unrelated err should not be a timeout")
	}
	if !isTimeout(errors.New("i/o timeout")) {
		t.Error("phrase match should trigger")
	}
}

func generateTestKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return sshPub
}
