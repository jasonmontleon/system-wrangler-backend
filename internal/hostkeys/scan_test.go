// SPDX-License-Identifier: Apache-2.0

package hostkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/systems"
)

// fakeExec returns canned bytes per command. Sufficient for the
// scan tests; the real ansible.Executor lives in another package.
type fakeExec struct {
	stdout []byte
	stderr []byte
	exit   int
	err    error
	calls  int
}

func (f *fakeExec) Run(_ context.Context, _ string, _ []string, _ []string, _ []byte) ([]byte, []byte, int, error) {
	f.calls++
	return f.stdout, f.stderr, f.exit, f.err
}

func TestParseKeyscanHappyPath(t *testing.T) {
	input := `# h-1.example SSH-2.0-OpenSSH_9.0
h-1.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7UTr8K9bV7B0FxMo3a7Q4Df3hQ1lr8sLs9c+EYy/Jh

`
	got, err := ParseKeyscan([]byte(input))
	if err != nil {
		t.Fatalf("ParseKeyscan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Algorithm != "ssh-ed25519" {
		t.Errorf("algorithm = %q", got[0].Algorithm)
	}
	if !strings.HasPrefix(got[0].Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q (no SHA256: prefix)", got[0].Fingerprint)
	}
}

func TestParseKeyscanSkipsMalformed(t *testing.T) {
	input := `h-1.example onlytwo
h-1.example ssh-ed25519 not-valid-base64!!!
`
	got, err := ParseKeyscan([]byte(input))
	if err != nil {
		t.Fatalf("ParseKeyscan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

func TestParseKeyscanEmpty(t *testing.T) {
	got, err := ParseKeyscan(nil)
	if err != nil {
		t.Fatalf("ParseKeyscan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d", len(got))
	}
}

// genKeyscanLine produces a real ed25519 ssh-keyscan-style line so
// Scan's full path (parse → fingerprint → RecordPending) is
// exercised end-to-end without shelling out.
func genKeyscanLine(hostname string) (string, string) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	blob := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	parts := strings.SplitN(blob, " ", 2)
	return hostname + " " + parts[0] + " " + parts[1] + "\n", ssh.FingerprintSHA256(sshPub)
}

func TestScanRecordsPendingAndEmitsAudit(t *testing.T) {
	store, sysStore := newStore(t)
	sys, err := sysStore.Create(systems.SystemInput{Name: "host-s", Hostname: "host-s.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(store.db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	line, fp := genKeyscanLine(sys.Hostname)
	fx := &fakeExec{stdout: []byte(line), exit: 0}

	out, err := Scan(context.Background(), fx, store, auditStore, sys)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if out[0].State != StatePending || out[0].Fingerprint != fp {
		t.Errorf("out[0] = %#v, want pending fp=%q", out[0], fp)
	}
	// audit row emitted.
	rows, _, _ := auditStore.ListQuery(audit.Query{Action: "system.host_key.pending", Limit: 5})
	if len(rows) != 1 {
		t.Errorf("pending audit rows = %d, want 1", len(rows))
	}
}

func TestScanWithoutAuditStore(t *testing.T) {
	store, sysStore := newStore(t)
	sys, err := sysStore.Create(systems.SystemInput{Name: "host-t", Hostname: "host-t.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	line, _ := genKeyscanLine(sys.Hostname)
	fx := &fakeExec{stdout: []byte(line), exit: 0}
	out, err := Scan(context.Background(), fx, store, nil, sys)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(out) != 1 {
		t.Errorf("len(out) = %d, want 1", len(out))
	}
}

func TestScanNilExecutor(t *testing.T) {
	store, sysStore := newStore(t)
	sys, err := sysStore.Create(systems.SystemInput{Name: "host-u", Hostname: "host-u.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	if _, err := Scan(context.Background(), nil, store, nil, sys); err == nil {
		t.Error("expected an error for nil executor")
	}
}

func TestScanExecutorError(t *testing.T) {
	store, sysStore := newStore(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "host-v", Hostname: "host-v.example"})
	fx := &fakeExec{err: errors.New("ssh-keyscan: not found")}
	if _, err := Scan(context.Background(), fx, store, nil, sys); err == nil {
		t.Error("expected the executor error to bubble up")
	}
}

func TestScanExitNonZeroWithNoOutput(t *testing.T) {
	store, sysStore := newStore(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "host-w", Hostname: "host-w.example"})
	fx := &fakeExec{exit: 1}
	if _, err := Scan(context.Background(), fx, store, nil, sys); err == nil {
		t.Error("expected an error when ssh-keyscan exits non-zero with no output")
	}
}
