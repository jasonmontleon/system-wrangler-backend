// SPDX-License-Identifier: Apache-2.0

package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"system-wrangler-backend/internal/credentials"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/hostkeys"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/systems"
)

// sshFixture is an in-process SSH server that proxies "direct-tcpip"
// channel requests to a configurable backend HTTP server. It exists
// so the FetchOverTunnel code path runs end-to-end without a real SSH
// daemon: the test generates a host keypair, a client keypair, and a
// backend HTTP server; the production proxy code dials through this
// fixture exactly as it would against sshd.
type sshFixture struct {
	listener     net.Listener
	port         int
	hostSigner   ssh.Signer
	clientSigner ssh.Signer
	clientPriv   ed25519.PrivateKey
	hostKeyAlgo  string
	hostKeyFP    string
	backend      *httptest.Server

	wg     sync.WaitGroup
	stopCh chan struct{}
}

func newSSHFixture(t *testing.T, backend http.Handler) *sshFixture {
	t.Helper()

	hostPub, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host keygen: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	hostSSHPub, err := ssh.NewPublicKey(hostPub)
	if err != nil {
		t.Fatalf("host ssh pub: %v", err)
	}

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client keygen: %v", err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	backendSrv := httptest.NewServer(backend)

	f := &sshFixture{
		listener:     ln,
		port:         ln.Addr().(*net.TCPAddr).Port,
		hostSigner:   hostSigner,
		clientSigner: clientSigner,
		clientPriv:   clientPriv,
		hostKeyAlgo:  hostSSHPub.Type(),
		hostKeyFP:    ssh.FingerprintSHA256(hostSSHPub),
		backend:      backendSrv,
		stopCh:       make(chan struct{}),
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if ssh.FingerprintSHA256(k) == ssh.FingerprintSHA256(clientSigner.PublicKey()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("sshfixture: rejected key %s", ssh.FingerprintSHA256(k))
		},
	}
	cfg.AddHostKey(hostSigner)

	f.wg.Add(1)
	go f.acceptLoop(cfg)
	t.Cleanup(f.stop)
	return f
}

func (f *sshFixture) stop() {
	select {
	case <-f.stopCh:
		return
	default:
	}
	close(f.stopCh)
	_ = f.listener.Close()
	f.backend.Close()
	f.wg.Wait()
}

func (f *sshFixture) acceptLoop(cfg *ssh.ServerConfig) {
	defer f.wg.Done()
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		f.wg.Add(1)
		go f.handleConn(conn, cfg)
	}
}

func (f *sshFixture) handleConn(nConn net.Conn, cfg *ssh.ServerConfig) {
	defer f.wg.Done()
	defer func() { _ = nConn.Close() }()

	_, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "direct-tcpip" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only direct-tcpip is supported")
			continue
		}
		f.wg.Add(1)
		go f.handleDirectTCP(newCh)
	}
}

func (f *sshFixture) handleDirectTCP(newCh ssh.NewChannel) {
	defer f.wg.Done()

	ch, reqs, err := newCh.Accept()
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	defer func() { _ = ch.Close() }()

	// The fixture ignores the client-supplied direct-tcpip target and
	// routes every connection to its backend HTTP server.
	upstream, err := net.Dial("tcp", f.backend.Listener.Addr().String())
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, ch); done <- struct{}{} }()
	go func() { _, _ = io.Copy(ch, upstream); done <- struct{}{} }()
	<-done
}

// proxyRig wires a Proxy against an in-process SSH server, a real
// vault, a real credentials store, and a real hostkeys store — the
// full set of dependencies FetchOverTunnel touches.
type proxyRig struct {
	proxy   *Proxy
	fixture *sshFixture
	system  systems.System
	hk      *hostkeys.SQLiteStore
}

func newProxyRig(t *testing.T, backend http.Handler) *proxyRig {
	t.Helper()

	dsn := "file:" + filepath.Join(t.TempDir(), "rig.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems store: %v", err)
	}
	if _, err := groups.NewSQLiteStore(db); err != nil {
		t.Fatalf("groups store: %v", err)
	}
	credStore, err := credentials.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("credentials store: %v", err)
	}
	hkStore, err := hostkeys.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("hostkeys store: %v", err)
	}

	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	vault, err := secrets.NewVaultFromKey(keyBytes)
	if err != nil {
		t.Fatalf("vault: %v", err)
	}

	f := newSSHFixture(t, backend)

	pemBlock, err := ssh.MarshalPrivateKey(f.clientPriv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	sealed, err := credentials.SealWith(vault, pemBytes)
	if err != nil {
		t.Fatalf("SealWith: %v", err)
	}

	sys, err := sysStore.Create(systems.SystemInput{Name: "rig", Hostname: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Create system: %v", err)
	}

	if _, err := credStore.Upsert(credentials.Slot{
		ScopeKind:   credentials.ScopeGlobal,
		AnsibleUser: "ansible",
		PublicKey:   string(ssh.MarshalAuthorizedKey(f.clientSigner.PublicKey())),
		PrivateKey:  sealed,
		Origin:      credentials.OriginSWGenerated,
	}); err != nil {
		t.Fatalf("creds upsert: %v", err)
	}

	if _, err := hkStore.RecordPending(sys.ID, f.hostKeyAlgo, "AAAA", f.hostKeyFP); err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	if _, _, err := hkStore.Accept(sys.ID, f.hostKeyAlgo, f.hostKeyFP, "u"); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	p := &Proxy{
		Systems:      sysStore,
		Credentials:  credStore,
		HostKeys:     hkStore,
		Vault:        vault,
		SSHPort:      f.port,
		DialTimeout:  2 * time.Second,
		FetchTimeout: 2 * time.Second,
	}
	return &proxyRig{proxy: p, fixture: f, system: sys, hk: hkStore}
}

func TestFetchOverTunnelEndToEndSuccess(t *testing.T) {
	body := "node_load1 0.42\n"
	rig := newProxyRig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	got, err := rig.proxy.FetchOverTunnel(context.Background(), rig.system.ID, "127.0.0.1", 9100, "/metrics")
	if err != nil {
		t.Fatalf("FetchOverTunnel: %v", err)
	}
	if string(got) != body {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestFetchOverTunnelUpstreamNon2xx(t *testing.T) {
	rig := newProxyRig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	_, err := rig.proxy.FetchOverTunnel(context.Background(), rig.system.ID, "127.0.0.1", 9100, "/metrics")
	if !errors.Is(err, ErrUpstream) {
		t.Errorf("err = %v, want ErrUpstream", err)
	}
}

func TestFetchOverTunnelContextCancelled(t *testing.T) {
	rig := newProxyRig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := rig.proxy.FetchOverTunnel(ctx, rig.system.ID, "127.0.0.1", 9100, "/metrics")
	if err == nil {
		t.Error("FetchOverTunnel with cancelled ctx = nil, want error")
	}
}

func TestFetchOverTunnelHostKeyMismatch(t *testing.T) {
	rig := newProxyRig(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	// Replace the accepted host key with a different fingerprint so
	// the callback rejects the server's real key on handshake.
	if err := rig.hk.Delete(acceptedKeyID(t, rig)); err != nil {
		t.Fatalf("Delete accepted: %v", err)
	}
	if _, err := rig.hk.RecordPending(rig.system.ID, rig.fixture.hostKeyAlgo, "AAAA", "SHA256:not-the-real-fp"); err != nil {
		t.Fatalf("RecordPending: %v", err)
	}
	if _, _, err := rig.hk.Accept(rig.system.ID, rig.fixture.hostKeyAlgo, "SHA256:not-the-real-fp", "u"); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	_, err := rig.proxy.FetchOverTunnel(context.Background(), rig.system.ID, "127.0.0.1", 9100, "/metrics")
	if err == nil {
		t.Fatal("expected host-key mismatch error, got nil")
	}
}

func TestFetchOverTunnelNoHostKeySurfacesErrNoHostKey(t *testing.T) {
	rig := newProxyRig(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	if err := rig.hk.Delete(acceptedKeyID(t, rig)); err != nil {
		t.Fatalf("Delete accepted: %v", err)
	}
	_, err := rig.proxy.FetchOverTunnel(context.Background(), rig.system.ID, "127.0.0.1", 9100, "/metrics")
	if !errors.Is(err, ErrNoHostKey) {
		t.Errorf("err = %v, want ErrNoHostKey", err)
	}
}

func TestFetchOverTunnelSequentialFetches(t *testing.T) {
	rig := newProxyRig(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	for i := 0; i < 2; i++ {
		body, err := rig.proxy.FetchOverTunnel(context.Background(), rig.system.ID, "127.0.0.1", 9100, "/metrics")
		if err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
		if string(body) != "ok" {
			t.Errorf("fetch %d body = %q", i, body)
		}
	}
}

func acceptedKeyID(t *testing.T, rig *proxyRig) string {
	t.Helper()
	rows, err := rig.hk.AcceptedFor(rig.system.ID)
	if err != nil {
		t.Fatalf("AcceptedFor: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("AcceptedFor: got %d rows, want 1", len(rows))
	}
	return rows[0].ID
}
