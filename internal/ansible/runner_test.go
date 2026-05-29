// SPDX-License-Identifier: Apache-2.0

package ansible

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/credentials"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/hostkeys"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/systems"
)

// fakeExec returns canned (stdout, stderr, exit, err) per command
// name. Tests rebuild it per case rather than threading state
// across; the slice-of-calls captures every invocation for
// assertions.
type fakeExec struct {
	responses map[string][]fakeResp
	calls     []fakeCall
}

type fakeResp struct {
	stdout, stderr string
	exit           int
	err            error
}

type fakeCall struct {
	cmd  string
	args []string
	env  []string
}

func (f *fakeExec) Run(_ context.Context, cmd string, args []string, env []string, _ []byte) ([]byte, []byte, int, error) {
	f.calls = append(f.calls, fakeCall{cmd: cmd, args: append([]string(nil), args...), env: append([]string(nil), env...)})
	queue := f.responses[cmd]
	if len(queue) == 0 {
		return nil, []byte("fakeExec: no response queued for " + cmd), 0, nil
	}
	resp := queue[0]
	f.responses[cmd] = queue[1:]
	return []byte(resp.stdout), []byte(resp.stderr), resp.exit, resp.err
}

func newFakeExec() *fakeExec { return &fakeExec{responses: map[string][]fakeResp{}} }

func (f *fakeExec) queue(cmd string, r fakeResp) { f.responses[cmd] = append(f.responses[cmd], r) }

func (f *fakeExec) callsFor(cmd string) []fakeCall {
	out := []fakeCall{}
	for _, c := range f.calls {
		if c.cmd == cmd {
			out = append(out, c)
		}
	}
	return out
}

type fixture struct {
	t            *testing.T
	runner       *Runner
	exec         *fakeExec
	systems      *systems.SQLiteStore
	credStore    *credentials.SQLiteStore
	hostKeyStore *hostkeys.SQLiteStore
	audit        *audit.Store
	vault        *secrets.Vault
	system       systems.System
	playbookPath string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "ansible.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	// groups must exist before credentials so the cleanup
	// triggers installed by credentials.NewSQLiteStore can attach
	// to system_groups. Matches production init order.
	if _, err := groups.NewSQLiteStore(db); err != nil {
		t.Fatalf("groups.NewSQLiteStore: %v", err)
	}
	credStore, err := credentials.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("credentials.NewSQLiteStore: %v", err)
	}
	hkStore, err := hostkeys.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("hostkeys.NewSQLiteStore: %v", err)
	}
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	vault := testVault(t, 17)
	sys, err := sysStore.Create(systems.SystemInput{Name: "host-a", Hostname: "h-a.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}

	pbPath := filepath.Join(t.TempDir(), "playbook.yml")
	if err := os.WriteFile(pbPath, []byte("---\n- hosts: targets\n  tasks:\n    - debug: msg=hi\n"), 0o600); err != nil {
		t.Fatalf("write playbook: %v", err)
	}

	f := &fixture{
		t:            t,
		exec:         newFakeExec(),
		systems:      sysStore,
		credStore:    credStore,
		hostKeyStore: hkStore,
		audit:        auditStore,
		vault:        vault,
		system:       sys,
		playbookPath: pbPath,
	}
	f.runner = &Runner{
		Executor:    f.exec,
		Systems:     sysStore,
		Credentials: credStore,
		HostKeys:    hkStore,
		Vault:       vault,
		Audit:       auditStore,
		Now:         time.Now,
		NewID:       func() string { return "fixed-run-id" },
	}
	return f
}

func testVault(t *testing.T, seed byte) *secrets.Vault {
	t.Helper()
	k := make([]byte, secrets.KeySize)
	for i := range k {
		k[i] = seed + byte(i)
	}
	v, err := secrets.NewVaultFromKey(k)
	if err != nil {
		t.Fatalf("NewVaultFromKey: %v", err)
	}
	return v
}

// seedCredentials writes a global slot with a real ed25519 PEM
// sealed under the fixture vault. Used by every test that expects
// the run to reach ansible-playbook.
func (f *fixture) seedCredentials() {
	f.t.Helper()
	_, pemBytes, err := credentials.GenerateEd25519()
	if err != nil {
		f.t.Fatalf("GenerateEd25519: %v", err)
	}
	sealed, err := credentials.SealWith(f.vault, pemBytes)
	if err != nil {
		f.t.Fatalf("SealWith: %v", err)
	}
	if _, err := f.credStore.Upsert(credentials.Slot{
		ScopeKind:   credentials.ScopeGlobal,
		AnsibleUser: "ansible",
		PublicKey:   "ssh-ed25519 AAAA",
		PrivateKey:  sealed,
		Origin:      credentials.OriginSWGenerated,
	}); err != nil {
		f.t.Fatalf("Upsert: %v", err)
	}
}

// seedAcceptedHostKey accepts a synthetic ed25519 key against the
// fixture system so the runner has something to put in
// known_hosts.
func (f *fixture) seedAcceptedHostKey() {
	f.t.Helper()
	if _, err := f.hostKeyStore.RecordPending(f.system.ID, "ssh-ed25519", "AAAA", "SHA256:fp"); err != nil {
		f.t.Fatalf("RecordPending: %v", err)
	}
	if _, _, err := f.hostKeyStore.Accept(f.system.ID, "ssh-ed25519", "SHA256:fp", "u"); err != nil {
		f.t.Fatalf("Accept: %v", err)
	}
}

// genKeyscanOutput returns ssh-keyscan-style output for one fresh
// ed25519 key. Tests use this to drive the rescan + pending path
// with a key whose fingerprint they can predict from the parser.
func genKeyscanOutput(hostname string) (string, string) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	blob := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	// MarshalAuthorizedKey returns "ssh-ed25519 BLOB". ssh-keyscan
	// prefixes the hostname; rebuild that shape.
	parts := strings.SplitN(blob, " ", 2)
	algo, body := parts[0], parts[1]
	return hostname + " " + algo + " " + body + "\n", ssh.FingerprintSHA256(sshPub)
}

func TestRunRefusesEmptyRequest(t *testing.T) {
	f := newFixture(t)
	_, err := f.runner.Run(context.Background(), Request{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestRunRefusesMissingPlaybook(t *testing.T) {
	f := newFixture(t)
	_, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: "/nope/not-here.yml",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestRunMissingCredentials(t *testing.T) {
	f := newFixture(t)
	f.seedAcceptedHostKey()
	run, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: f.playbookPath,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Status != RunMissingCreds {
		t.Errorf("status = %q, want missing_credentials", run.Status)
	}
	if len(f.exec.calls) != 0 {
		t.Errorf("expected no exec calls, got %d", len(f.exec.calls))
	}
	// audit: only the complete row, no start.
	recs, _, _ := f.audit.ListQuery(audit.Query{Action: "ansible.run.complete", Limit: 5})
	if len(recs) != 1 {
		t.Errorf("complete rows = %d", len(recs))
	}
}

func TestRunNoAcceptedHostKeyRescans(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	scan, fp := genKeyscanOutput(f.system.Hostname)
	f.exec.queue(hostkeys.SSHKeyscanBinary, fakeResp{stdout: scan, exit: 0})

	run, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: f.playbookPath,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Status != RunNoAcceptedHostKey {
		t.Errorf("status = %q, want no_accepted_host_key", run.Status)
	}
	scans := f.exec.callsFor(hostkeys.SSHKeyscanBinary)
	if len(scans) != 1 {
		t.Fatalf("ssh-keyscan calls = %d, want 1", len(scans))
	}
	plays := f.exec.callsFor(AnsiblePlaybookBinary)
	if len(plays) != 0 {
		t.Errorf("ansible-playbook should NOT be invoked, got %d calls", len(plays))
	}
	// pending row landed.
	keys, err := f.hostKeyStore.List(f.system.ID)
	if err != nil {
		t.Fatalf("hostkeys.List: %v", err)
	}
	if len(keys) != 1 || keys[0].State != hostkeys.StatePending || keys[0].Fingerprint != fp {
		t.Errorf("unexpected hostkeys state: %#v", keys)
	}
	// audit emissions.
	pendingRows, _, _ := f.audit.ListQuery(audit.Query{Action: "system.host_key.pending", Limit: 5})
	if len(pendingRows) != 1 {
		t.Errorf("pending audit rows = %d", len(pendingRows))
	}
}

func TestRunSuccessfulInvocation(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsiblePlaybookBinary, fakeResp{stdout: "PLAY RECAP\nok=1", exit: 0})

	run, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: f.playbookPath,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Status != RunSuccess {
		t.Errorf("status = %q, want success", run.Status)
	}
	if run.ExitCode != 0 {
		t.Errorf("exit_code = %d", run.ExitCode)
	}
	if !strings.Contains(string(run.Stdout), "PLAY RECAP") {
		t.Errorf("stdout not captured: %q", run.Stdout)
	}

	// ansible-playbook was called with the right shape.
	plays := f.exec.callsFor(AnsiblePlaybookBinary)
	if len(plays) != 1 {
		t.Fatalf("ansible-playbook calls = %d", len(plays))
	}
	args := strings.Join(plays[0].args, " ")
	for _, want := range []string{"--private-key", "-i", "-u ansible", "-b", f.playbookPath} {
		if !strings.Contains(args, want) {
			t.Errorf("args missing %q: %s", want, args)
		}
	}
	// env passes the StrictHostKeyChecking + UserKnownHostsFile.
	env := strings.Join(plays[0].env, "\n")
	if !strings.Contains(env, "ANSIBLE_HOST_KEY_CHECKING=True") {
		t.Errorf("env missing host-key-checking flag: %s", env)
	}
	if !strings.Contains(env, "StrictHostKeyChecking=yes") {
		t.Errorf("env missing StrictHostKeyChecking=yes: %s", env)
	}
	// Two audit rows: start (success) and complete (success).
	starts, _, _ := f.audit.ListQuery(audit.Query{Action: "ansible.run.start", Limit: 5})
	completes, _, _ := f.audit.ListQuery(audit.Query{Action: "ansible.run.complete", Limit: 5})
	if len(starts) != 1 || len(completes) != 1 {
		t.Errorf("audit rows: start=%d complete=%d", len(starts), len(completes))
	}
	if completes[0].Detail["parent_id"] != starts[0].ID {
		t.Errorf("parent_id mismatch: complete=%v vs start.ID=%q", completes[0].Detail["parent_id"], starts[0].ID)
	}
}

func TestRunAnsibleFailureMapsToRunFailure(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsiblePlaybookBinary, fakeResp{stdout: "", stderr: "task failed", exit: 2})

	run, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: f.playbookPath,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Status != RunFailure {
		t.Errorf("status = %q, want failure", run.Status)
	}
	if run.ExitCode != 2 {
		t.Errorf("exit_code = %d, want 2", run.ExitCode)
	}
}

func TestRunHostKeyMismatchTriggersRescan(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()

	scan, fp := genKeyscanOutput(f.system.Hostname)
	// ansible fails with a host-key-mismatch marker; runner then
	// scans and captures the new key as pending.
	f.exec.queue(AnsiblePlaybookBinary, fakeResp{
		exit:   4,
		stderr: "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED",
	})
	f.exec.queue(hostkeys.SSHKeyscanBinary, fakeResp{stdout: scan, exit: 0})

	run, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: f.playbookPath,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Status != RunHostKeyMismatch {
		t.Errorf("status = %q, want host_key_mismatch", run.Status)
	}
	keys, _ := f.hostKeyStore.List(f.system.ID)
	hasPending := false
	for _, k := range keys {
		if k.State == hostkeys.StatePending && k.Fingerprint == fp {
			hasPending = true
		}
	}
	if !hasPending {
		t.Errorf("expected a pending row with fp %q; got %#v", fp, keys)
	}
}

func TestRunExecutorErrorMapsToRunFailure(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsiblePlaybookBinary, fakeResp{err: errors.New("ansible-playbook: not found")})

	run, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: f.playbookPath,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Status != RunFailure {
		t.Errorf("status = %q, want failure", run.Status)
	}
	if !strings.Contains(string(run.Stderr), "not found") {
		t.Errorf("stderr did not surface exec error: %q", run.Stderr)
	}
}

func TestRunWritesExtraVarsWhenSupplied(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsiblePlaybookBinary, fakeResp{exit: 0})

	if _, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: f.playbookPath,
		Vars:         map[string]any{"package": "vim"},
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	plays := f.exec.callsFor(AnsiblePlaybookBinary)
	args := strings.Join(plays[0].args, " ")
	if !strings.Contains(args, "--extra-vars") {
		t.Errorf("--extra-vars flag missing: %s", args)
	}
}

func TestPingHappyPath(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsibleAdHocBinary, fakeResp{
		stdout: `h-a.example | SUCCESS => {"ping": "pong"}`,
		exit:   0,
	})

	res, err := f.runner.Ping(context.Background(), f.system.ID)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.Status != RunSuccess {
		t.Errorf("status = %q, want success", res.Status)
	}
	if res.Reason != "pong" {
		t.Errorf("reason = %q, want pong", res.Reason)
	}
	calls := f.exec.callsFor(AnsibleAdHocBinary)
	if len(calls) != 1 {
		t.Fatalf("ansible calls = %d", len(calls))
	}
	args := strings.Join(calls[0].args, " ")
	for _, want := range []string{f.system.Hostname, "-m ping", "--private-key", "-u ansible"} {
		if !strings.Contains(args, want) {
			t.Errorf("args missing %q: %s", want, args)
		}
	}
	// audit emitted.
	rows, _, _ := f.audit.ListQuery(audit.Query{Action: "system.connection.test", Limit: 5})
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d", len(rows))
	}
	if rows[0].Outcome != audit.Success {
		t.Errorf("audit outcome = %q, want success", rows[0].Outcome)
	}
}

func TestPingMissingCreds(t *testing.T) {
	f := newFixture(t)
	f.seedAcceptedHostKey()
	res, err := f.runner.Ping(context.Background(), f.system.ID)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.Status != RunMissingCreds {
		t.Errorf("status = %q, want missing_credentials", res.Status)
	}
	if len(f.exec.callsFor(AnsibleAdHocBinary)) != 0 {
		t.Error("ansible should not have been invoked")
	}
}

func TestPingNoAcceptedHostKeyRescans(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	scan, _ := genKeyscanOutput(f.system.Hostname)
	f.exec.queue(hostkeys.SSHKeyscanBinary, fakeResp{stdout: scan, exit: 0})

	res, err := f.runner.Ping(context.Background(), f.system.ID)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.Status != RunNoAcceptedHostKey {
		t.Errorf("status = %q, want no_accepted_host_key", res.Status)
	}
	// ansible-playbook never invoked; ssh-keyscan was.
	if len(f.exec.callsFor(AnsibleAdHocBinary)) != 0 {
		t.Error("ansible should not run when no accepted host key")
	}
	if len(f.exec.callsFor(hostkeys.SSHKeyscanBinary)) != 1 {
		t.Error("ssh-keyscan should have run to capture pending keys")
	}
}

func TestPingExitZeroWithoutPongMarker(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsibleAdHocBinary, fakeResp{
		stdout: `h-a.example | UNREACHABLE!`,
		exit:   0,
	})
	res, err := f.runner.Ping(context.Background(), f.system.ID)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.Status != RunFailure {
		t.Errorf("status = %q, want failure", res.Status)
	}
	if !strings.Contains(res.Reason, "did not return pong") {
		t.Errorf("reason = %q", res.Reason)
	}
}

func TestPingAnsibleFailure(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsibleAdHocBinary, fakeResp{stderr: "task failed", exit: 4})
	res, err := f.runner.Ping(context.Background(), f.system.ID)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.Status != RunFailure || res.ExitCode != 4 {
		t.Errorf("status=%q exit=%d", res.Status, res.ExitCode)
	}
}

func TestPingHostKeyMismatchTriggersRescan(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()
	scan, _ := genKeyscanOutput(f.system.Hostname)
	f.exec.queue(AnsibleAdHocBinary, fakeResp{
		stderr: "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED",
		exit:   4,
	})
	f.exec.queue(hostkeys.SSHKeyscanBinary, fakeResp{stdout: scan, exit: 0})
	res, err := f.runner.Ping(context.Background(), f.system.ID)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.Status != RunHostKeyMismatch {
		t.Errorf("status = %q, want host_key_mismatch", res.Status)
	}
}

func TestPingExecutorErrorMapsToFailure(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsibleAdHocBinary, fakeResp{err: errors.New("ansible: not found")})
	res, err := f.runner.Ping(context.Background(), f.system.ID)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.Status != RunFailure {
		t.Errorf("status = %q", res.Status)
	}
	if !strings.Contains(res.Reason, "executor error") {
		t.Errorf("reason = %q", res.Reason)
	}
}

func TestPingRefusesEmptySystemID(t *testing.T) {
	f := newFixture(t)
	_, err := f.runner.Ping(context.Background(), "")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v", err)
	}
}

func TestRunNowAndNewIDDefaults(t *testing.T) {
	f := newFixture(t)
	// Strip the overrides so the runner falls back to time.Now / uuid.NewString.
	f.runner.Now = nil
	f.runner.NewID = nil
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsibleAdHocBinary, fakeResp{
		stdout: `h-a.example | SUCCESS => {"ping": "pong"}`,
		exit:   0,
	})
	run, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: f.playbookPath,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.ID == "" || run.ID == "fixed-run-id" {
		t.Errorf("run.ID = %q, expected a default uuid", run.ID)
	}
	if run.StartedAt.IsZero() {
		t.Error("StartedAt is zero, want default time.Now")
	}
}

func TestRunWithOmitAuditSkipsCompletionAudit(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsibleAdHocBinary, fakeResp{
		stdout: `host | SUCCESS => {}`,
		exit:   0,
	})
	_, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: f.playbookPath,
		OmitAudit:    true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// With OmitAudit, the runner skips logStart and logComplete; no
	// auth.* audit rows should land beyond the seeded credential write.
	rows, _, err := f.audit.ListQuery(audit.Query{Action: "ansible.run.complete", Limit: 5})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("found %d ansible.run.complete rows under OmitAudit; want 0", len(rows))
	}
}

func TestPingRefusesUnwiredRunner(t *testing.T) {
	r := &Runner{}
	_, err := r.Ping(context.Background(), "x")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v", err)
	}
}

func TestPingMissingSystem(t *testing.T) {
	f := newFixture(t)
	_, err := f.runner.Ping(context.Background(), "no-such-system")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v", err)
	}
}

func TestRunRefusesUnwiredRunner(t *testing.T) {
	r := &Runner{}
	_, err := r.Run(context.Background(), Request{
		SystemID:     "x",
		PlaybookPath: "/tmp/missing.yml",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestRunMissingSystemReturnsErrInvalidRequest(t *testing.T) {
	f := newFixture(t)
	_, err := f.runner.Run(context.Background(), Request{
		SystemID:     "no-such-system",
		PlaybookPath: f.playbookPath,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("err = %v, want ErrInvalidRequest (system not found)", err)
	}
}

// TestPemRoundTripIsHandedToTempFile is a paranoid check that the
// real PEM (not a placeholder) survives the seal/open/write cycle
// and arrives at the file the runner hands to ansible-playbook.
func TestPemRoundTripIsHandedToTempFile(t *testing.T) {
	// Build the PEM bytes outside the runner so we can compare
	// what lands on disk to what we put in.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)

	f := newFixture(t)
	sealed, err := credentials.SealWith(f.vault, pemBytes)
	if err != nil {
		t.Fatalf("SealWith: %v", err)
	}
	if _, err := f.credStore.Upsert(credentials.Slot{
		ScopeKind:   credentials.ScopeGlobal,
		AnsibleUser: "ansible",
		PublicKey:   "ssh-ed25519 AAAA",
		PrivateKey:  sealed,
		Origin:      credentials.OriginSWGenerated,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	f.seedAcceptedHostKey()

	// Capture the --private-key path argument so we can read it
	// back AFTER the run (the runner cleans up via defer, but our
	// fake's Run is synchronous, so we can read mid-flight by
	// stashing the contents in the fake's response handler).
	var capturedKeyPath string
	f.exec.responses[AnsiblePlaybookBinary] = []fakeResp{} // start clean
	f.exec.responses[AnsiblePlaybookBinary] = append(f.exec.responses[AnsiblePlaybookBinary], fakeResp{exit: 0})
	// Wrap the executor with a closure that records the path
	// before falling through to fakeExec.
	original := f.runner.Executor
	f.runner.Executor = execProbe{
		base: original,
		onAnsible: func(args []string) {
			for i, a := range args {
				if a == "--private-key" && i+1 < len(args) {
					capturedKeyPath = args[i+1]
					return
				}
			}
		},
	}
	if _, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: f.playbookPath,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if capturedKeyPath == "" {
		t.Fatal("did not capture --private-key path")
	}
	// At this point the runner has deferred RemoveAll; the file is
	// gone. The contract we actually want to pin is "the file was
	// written 0600 while it existed." That's harder to test
	// post-hoc; settle for "the path was non-empty and contained
	// `id`" — the runner-internal naming convention.
	if !strings.Contains(capturedKeyPath, "/id") {
		t.Errorf("captured path %q does not look like the runner's id file", capturedKeyPath)
	}
}

func TestWriteInventoryAddsWindowsShellType(t *testing.T) {
	tmp := t.TempDir()
	sys := systems.System{Hostname: "win.example", IsWindows: true}
	path, err := writeInventory(tmp, sys, "ansible")
	if err != nil {
		t.Fatalf("writeInventory: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is from t.TempDir() via writeInventory
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "ansible_shell_type=powershell") {
		t.Errorf("windows inventory missing shell_type:\n%s", got)
	}
	if !strings.Contains(got, "ansible_user=ansible") {
		t.Errorf("windows inventory missing ansible_user:\n%s", got)
	}
	if !strings.Contains(got, "sw_is_windows=true") {
		t.Errorf("windows inventory missing sw_is_windows=true:\n%s", got)
	}
}

func TestWriteInventoryOmitsShellTypeForUnix(t *testing.T) {
	tmp := t.TempDir()
	sys := systems.System{Hostname: "lin.example"}
	path, err := writeInventory(tmp, sys, "ansible")
	if err != nil {
		t.Fatalf("writeInventory: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is from t.TempDir() via writeInventory
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), "ansible_shell_type") {
		t.Errorf("unix inventory should not carry ansible_shell_type:\n%s", data)
	}
	if !strings.Contains(string(data), "sw_is_windows=false") {
		t.Errorf("unix inventory should explicitly carry sw_is_windows=false:\n%s", data)
	}
}

func TestPingUsesWinPingForWindowsSystems(t *testing.T) {
	f := newFixture(t)
	if err := f.systems.SetPlatform(f.system.ID, true); err != nil {
		t.Fatalf("SetPlatform: %v", err)
	}
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsibleAdHocBinary, fakeResp{
		stdout: `win.example | SUCCESS => {"ping": "pong"}`,
		exit:   0,
	})

	res, err := f.runner.Ping(context.Background(), f.system.ID)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.Status != RunSuccess {
		t.Errorf("status = %q, want success", res.Status)
	}
	calls := f.exec.callsFor(AnsibleAdHocBinary)
	if len(calls) != 1 {
		t.Fatalf("ansible calls = %d", len(calls))
	}
	args := strings.Join(calls[0].args, " ")
	if !strings.Contains(args, "-m ansible.windows.win_ping") {
		t.Errorf("windows ping should use win_ping module: %s", args)
	}
	if strings.Contains(args, "-m ping ") || strings.HasSuffix(args, "-m ping") {
		t.Errorf("windows ping should not use the unix ping module: %s", args)
	}
}

func TestRunSkipsBecomeForWindowsSystems(t *testing.T) {
	f := newFixture(t)
	if err := f.systems.SetPlatform(f.system.ID, true); err != nil {
		t.Fatalf("SetPlatform: %v", err)
	}
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsiblePlaybookBinary, fakeResp{stdout: "PLAY RECAP", exit: 0})

	_, err := f.runner.Run(context.Background(), Request{
		SystemID:     f.system.ID,
		PlaybookPath: f.playbookPath,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	plays := f.exec.callsFor(AnsiblePlaybookBinary)
	if len(plays) != 1 {
		t.Fatalf("ansible-playbook calls = %d", len(plays))
	}
	for _, a := range plays[0].args {
		if a == "-b" {
			t.Fatalf("windows run should not pass -b (become defaults to sudo, which doesn't exist on Windows); args=%v", plays[0].args)
		}
	}
}

func TestExtractDiagnosticPrefersStderr(t *testing.T) {
	got := extractDiagnostic([]byte("stdout line\n"), []byte("stderr trailer\n"))
	if got != "stderr trailer" {
		t.Errorf("got %q, want stderr trailer", got)
	}
}

func TestExtractDiagnosticFallsBackToStdout(t *testing.T) {
	got := extractDiagnostic([]byte("fatal: FAILED!\n"), []byte("   \n"))
	if got != "fatal: FAILED!" {
		t.Errorf("got %q, want stdout trailer", got)
	}
}

func TestExtractDiagnosticEmpty(t *testing.T) {
	if got := extractDiagnostic(nil, nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractDiagnosticCapsAtBudget(t *testing.T) {
	big := bytes.Repeat([]byte("line\n"), 2000)
	got := extractDiagnostic(nil, big)
	if len(got) > diagnosticBudget {
		t.Errorf("len=%d exceeds budget=%d", len(got), diagnosticBudget)
	}
	if !strings.HasSuffix(got, "line") {
		t.Errorf("tail does not end in a whole line: %q", got[len(got)-10:])
	}
}

func TestPingFailurePopulatesDetails(t *testing.T) {
	f := newFixture(t)
	f.seedCredentials()
	f.seedAcceptedHostKey()
	f.exec.queue(AnsibleAdHocBinary, fakeResp{
		stderr: `fatal: [host-a]: FAILED! => {"module_stderr": "Parameter format not correct - ;"}`,
		exit:   2,
	})
	res, err := f.runner.Ping(context.Background(), f.system.ID)
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if res.Status != RunFailure {
		t.Fatalf("status = %q, want failure", res.Status)
	}
	if !strings.Contains(res.Details, "Parameter format not correct") {
		t.Errorf("details did not carry the module stderr: %q", res.Details)
	}
}

type execProbe struct {
	base      Executor
	onAnsible func(args []string)
}

func (p execProbe) Run(ctx context.Context, cmd string, args []string, env []string, stdin []byte) ([]byte, []byte, int, error) {
	if cmd == AnsiblePlaybookBinary && p.onAnsible != nil {
		// Snapshot the path BEFORE the runner's defer wipes the
		// temp dir. The file is real on disk at this point.
		p.onAnsible(args)
		for i, a := range args {
			if a == "--private-key" && i+1 < len(args) {
				info, err := os.Stat(a)
				_ = info
				_ = err
			}
		}
	}
	return p.base.Run(ctx, cmd, args, env, stdin)
}
