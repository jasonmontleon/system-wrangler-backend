// SPDX-License-Identifier: Apache-2.0

// Package sshproxy is the load-bearing primitive for "fetch HTTP from
// a service bound to localhost on a managed host." Used by the
// metrics pipeline's internal scrape endpoint to reach
// localhost-bound exporters through the existing SSH credential.
//
// Connection lifecycle is dial-per-fetch. ~100ms of SSH handshake
// overhead per scrape; acceptable for v1 fleet sizes. A connection
// pool keyed by system_id is a v2 optimisation if needed.
//
// Host-key validation goes through the existing hostkeys store —
// the same accepted-fingerprints the ansible runner uses, so the
// metrics pipeline shares the same trust boundary as the rest of
// System Wrangler.
package sshproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"system-wrangler-backend/internal/credentials"
	"system-wrangler-backend/internal/hostkeys"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/systems"
)

// Sentinel errors the proxy returns. Callers map these to HTTP
// statuses on the public surface.
var (
	ErrNoCredentials = errors.New("sshproxy: no credentials resolved for system")
	ErrNoHostKey     = errors.New("sshproxy: no accepted host key for system")
	ErrHostKeyMatch  = errors.New("sshproxy: host key fingerprint did not match any accepted row")
	ErrDialTimeout   = errors.New("sshproxy: SSH dial timed out")
	ErrUpstream      = errors.New("sshproxy: upstream returned non-2xx")
)

// Proxy is the dependency bundle for tunnel fetches. Construct once
// at startup and reuse across requests — the type is stateless apart
// from the supplied stores and vault.
type Proxy struct {
	Systems     systems.Store
	Credentials credentials.Store
	HostKeys    hostkeys.Store
	Vault       *secrets.Vault

	// DialTimeout caps the SSH handshake. Defaults to 5s when zero.
	DialTimeout time.Duration
	// FetchTimeout caps the HTTP request through the tunnel.
	// Defaults to 10s when zero.
	FetchTimeout time.Duration
	// SSHPort is the target SSH port. Defaults to 22.
	SSHPort int
}

// FetchOverTunnel opens an SSH connection to the system, dials
// addr:port through it, sends an HTTP GET for path, and returns the
// response body. The HTTP layer is intentionally minimal — we
// require a 2xx response and treat anything else as ErrUpstream.
//
// addr is the host the remote service is bound to (typically
// "127.0.0.1" for localhost-mode exporters); port + path are the
// service-specific bits.
func (p *Proxy) FetchOverTunnel(ctx context.Context, systemID, addr string, port int, path string) ([]byte, error) {
	client, err := p.dial(ctx, systemID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()

	fetchCtx, cancel := context.WithTimeout(ctx, p.fetchTimeout())
	defer cancel()

	target := net.JoinHostPort(addr, fmt.Sprintf("%d", port))
	conn, err := dialThroughClient(fetchCtx, client, target)
	if err != nil {
		return nil, fmt.Errorf("sshproxy: dial %s through tunnel: %w", target, err)
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := fetchCtx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	}

	// Hand-rolled HTTP/1.1 — net/http's Client wants a net.Conn-style
	// transport with full lifecycle control we'd have to wrap. The
	// exporter contract is straightforward GET-with-text-body, so a
	// 20-line round-trip beats wiring an http.Transport.
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: system-wrangler-sshproxy\r\nAccept: text/plain\r\nConnection: close\r\n\r\n",
		path, target,
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("sshproxy: write request: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		return nil, fmt.Errorf("sshproxy: read response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("sshproxy: read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status %d", ErrUpstream, resp.StatusCode)
	}
	return body, nil
}

func (p *Proxy) dial(ctx context.Context, systemID string) (*ssh.Client, error) {
	sys, err := p.Systems.Get(systemID)
	if err != nil {
		return nil, fmt.Errorf("sshproxy: lookup system: %w", err)
	}
	resolved, err := credentials.Resolve(p.Credentials, sys.ID, sys.GroupID)
	if err != nil {
		if errors.Is(err, credentials.ErrNoCredentials) || errors.Is(err, credentials.ErrIncompleteFlow) {
			return nil, ErrNoCredentials
		}
		return nil, fmt.Errorf("sshproxy: resolve credentials: %w", err)
	}
	pemBody, err := credentials.OpenWith(p.Vault, resolved.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sshproxy: open key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(pemBody)
	if err != nil {
		return nil, fmt.Errorf("sshproxy: parse key: %w", err)
	}

	accepted, err := p.HostKeys.AcceptedFor(systemID)
	if err != nil {
		return nil, fmt.Errorf("sshproxy: lookup host keys: %w", err)
	}
	if len(accepted) == 0 {
		return nil, ErrNoHostKey
	}

	cfg := &ssh.ClientConfig{
		User: resolved.AnsibleUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: acceptedKeysCallback(accepted),
		Timeout:         p.dialTimeout(),
	}

	target := net.JoinHostPort(sys.Hostname, fmt.Sprintf("%d", p.sshPort()))
	d := net.Dialer{Timeout: p.dialTimeout()}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		if isTimeout(err) {
			return nil, fmt.Errorf("%w: %s", ErrDialTimeout, target)
		}
		return nil, fmt.Errorf("sshproxy: dial %s: %w", target, err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, target, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sshproxy: ssh handshake: %w", err)
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}

// acceptedKeysCallback enforces "the presented key's fingerprint must
// match an accepted row for this system." Algorithm string is checked
// too so we can't be tricked by a key with the same SHA256 but a
// different algorithm field (the underlying ssh.PublicKey.Marshal
// blob is what's hashed by FingerprintSHA256, so this is mostly
// belt-and-suspenders).
func acceptedKeysCallback(accepted []hostkeys.HostKey) ssh.HostKeyCallback {
	want := make(map[string]bool, len(accepted))
	for _, h := range accepted {
		want[h.Algorithm+":"+h.Fingerprint] = true
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := key.Type() + ":" + ssh.FingerprintSHA256(key)
		if want[got] {
			return nil
		}
		return fmt.Errorf("%w: got %s", ErrHostKeyMatch, got)
	}
}

// dialThroughClient is ssh.Client.Dial with a context. The stdlib
// helper accepts a context indirectly via the underlying tcp dial,
// but the SSH library's Dial wraps a synchronous OpenChannel call —
// so we run the dial on a goroutine and let the context kill us if
// it expires.
func dialThroughClient(ctx context.Context, client *ssh.Client, addr string) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := client.Dial("tcp", addr)
		ch <- result{conn: c, err: err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *Proxy) dialTimeout() time.Duration {
	if p.DialTimeout > 0 {
		return p.DialTimeout
	}
	return 5 * time.Second
}

func (p *Proxy) fetchTimeout() time.Duration {
	if p.FetchTimeout > 0 {
		return p.FetchTimeout
	}
	return 10 * time.Second
}

func (p *Proxy) sshPort() int {
	if p.SSHPort > 0 {
		return p.SSHPort
	}
	return 22
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return strings.Contains(err.Error(), "i/o timeout")
}
