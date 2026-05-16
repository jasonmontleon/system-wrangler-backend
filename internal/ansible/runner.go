// SPDX-License-Identifier: Apache-2.0

package ansible

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/credentials"
	"system-wrangler-backend/internal/hostkeys"
	"system-wrangler-backend/internal/secrets"
	"system-wrangler-backend/internal/systems"
)

// AnsiblePlaybookBinary is the executable Runner spawns for playbook
// runs. Exposed so a test or a deployment-specific override can swap
// it. Defaults to "ansible-playbook" — assumed to be on PATH inside
// the container.
var AnsiblePlaybookBinary = "ansible-playbook"

// AnsibleAdHocBinary is the executable used by Ping for `ansible <host>
// -m ping`. Separate constant because the ad-hoc and playbook
// binaries are distinct (`ansible` vs `ansible-playbook`), and both
// are independently swappable for tests.
var AnsibleAdHocBinary = "ansible"

// Runner is the production entry point. All fields are required
// except Now / NewID (which default to time.Now / uuid.NewString).
type Runner struct {
	Executor    Executor
	Systems     systemsLookup
	Credentials credentials.Store
	HostKeys    hostkeys.Store
	Vault       *secrets.Vault
	Audit       *audit.Store

	Now   func() time.Time
	NewID func() string
}

// systemsLookup is the narrow slice of systems.Store this package
// needs. The real systems.SQLiteStore satisfies it.
type systemsLookup interface {
	Get(id string) (systems.System, error)
}

// Run executes one ansible play against one system. See the package
// doc for the full lifecycle. Returns (Run, error) where err is
// non-nil only for malformed requests or unrecoverable failures
// (vault missing, store I/O); ansible-level failures and policy
// gates (no creds, no accepted host key) flow through Run.Status.
func (r *Runner) Run(ctx context.Context, req Request) (Run, error) {
	if err := r.validate(req); err != nil {
		return Run{}, err
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}
	newID := r.NewID
	if newID == nil {
		newID = uuid.NewString
	}

	sys, err := r.Systems.Get(req.SystemID)
	if err != nil {
		if errors.Is(err, systems.ErrNotFound) {
			return Run{}, fmt.Errorf("%w: system %q not found", ErrInvalidRequest, req.SystemID)
		}
		return Run{}, fmt.Errorf("ansible: load system: %w", err)
	}

	run := Run{
		ID:         newID(),
		SystemID:   sys.ID,
		SystemName: sys.Name,
		Playbook:   filepath.Base(req.PlaybookPath),
		StartedAt:  now().UTC(),
	}

	resolved, credsOK := r.resolveCredentials(sys)
	if !credsOK {
		run.FinishedAt = now().UTC()
		run.Status = RunMissingCreds
		r.logComplete(ctx, run, "no credentials resolve for system; configure global/group/system slot")
		return run, nil
	}

	accepted, err := r.HostKeys.AcceptedFor(sys.ID)
	if err != nil {
		return Run{}, fmt.Errorf("ansible: load host keys: %w", err)
	}
	if len(accepted) == 0 {
		// First contact (or all keys deleted). Capture what the
		// host currently offers as pending and refuse the run —
		// the operator clicks Accept and retries.
		if err := r.scanAndRecord(ctx, sys); err != nil {
			slog.Warn("ansible: keyscan during no-accepted bailout", "err", err, "system_id", sys.ID)
		}
		run.FinishedAt = now().UTC()
		run.Status = RunNoAcceptedHostKey
		r.logComplete(ctx, run, "no accepted host key; review and accept in the UI before retrying")
		return run, nil
	}

	// Materialize per-run temp files. tmpDir gets cleaned on
	// return regardless of exit path.
	tmpDir, err := os.MkdirTemp("", "sw-ansible-")
	if err != nil {
		return Run{}, fmt.Errorf("ansible: mkdir tmp: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(tmpDir); rmErr != nil {
			slog.Warn("ansible: temp dir cleanup", "err", rmErr, "dir", tmpDir)
		}
	}()

	keyPath, err := r.writePrivateKey(tmpDir, resolved.PrivateKey)
	if err != nil {
		return Run{}, err
	}
	knownHostsPath, err := writeKnownHosts(tmpDir, sys.Hostname, accepted)
	if err != nil {
		return Run{}, err
	}
	inventoryPath, err := writeInventory(tmpDir, sys, resolved.AnsibleUser)
	if err != nil {
		return Run{}, err
	}
	var extraVarsArg []string
	if len(req.Vars) > 0 {
		extraVarsPath, err := writeExtraVars(tmpDir, req.Vars)
		if err != nil {
			return Run{}, err
		}
		extraVarsArg = []string{"--extra-vars", "@" + extraVarsPath}
	}

	r.logStart(ctx, run, resolved.AnsibleUser)

	args := []string{
		"-i", inventoryPath,
		"--private-key", keyPath,
		"-u", resolved.AnsibleUser,
		"-b",
		req.PlaybookPath,
	}
	args = append(args, extraVarsArg...)
	env := append(os.Environ(),
		"ANSIBLE_HOST_KEY_CHECKING=True",
		"ANSIBLE_SSH_COMMON_ARGS=-o UserKnownHostsFile="+knownHostsPath+
			" -o StrictHostKeyChecking=yes"+
			" -o ConnectTimeout=10",
	)

	stdout, stderr, exitCode, execErr := r.Executor.Run(ctx, AnsiblePlaybookBinary, args, env, nil)
	run.FinishedAt = now().UTC()
	run.Stdout = stdout
	run.Stderr = stderr
	run.ExitCode = exitCode

	if execErr != nil {
		// OS-level failure — ansible-playbook missing, ctx
		// cancelled, etc. Treat as RunFailure with the error
		// surfaced via stderr for the caller to see.
		run.Status = RunFailure
		if len(run.Stderr) == 0 {
			run.Stderr = []byte(execErr.Error())
		}
		r.logComplete(ctx, run, execErr.Error())
		return run, nil
	}

	if exitCode == 0 {
		run.Status = RunSuccess
		r.logComplete(ctx, run, "")
		return run, nil
	}

	// Non-zero exit. If the stderr smells like a host-key mismatch,
	// rescan and capture the offered key as pending so the operator
	// can compare. Otherwise just report failure.
	if looksLikeHostKeyMismatch(stderr) {
		if err := r.scanAndRecord(ctx, sys); err != nil {
			slog.Warn("ansible: keyscan during mismatch capture", "err", err, "system_id", sys.ID)
		}
		run.Status = RunHostKeyMismatch
		r.logComplete(ctx, run, "host key mismatch; review the new offered key in the UI")
		return run, nil
	}
	run.Status = RunFailure
	r.logComplete(ctx, run, "ansible-playbook exited non-zero")
	return run, nil
}

// PingResult is the outcome of an ad-hoc `ansible -m ping`
// invocation. Same status enum as Run so callers handle both via
// one switch.
type PingResult struct {
	SystemID   string
	SystemName string
	StartedAt  time.Time
	FinishedAt time.Time
	Status     RunStatus
	ExitCode   int
	Reason     string
	Stdout     []byte
	Stderr     []byte
}

// pongMarker is the substring `ansible -m ping` emits on success.
// We grep for it instead of parsing the JSON because the default
// callback's output is line-oriented and easier to recognise.
const pongMarker = `"ping": "pong"`

// Ping runs `ansible <host> -m ping` against the resolved system.
// Shares the credential + host-key gates and per-run temp-file
// setup with Run; the only differences are the ad-hoc binary, no
// playbook arg, no become, and an extra success-condition check on
// the stdout marker.
//
// Returns (PingResult, error) — error is only for malformed
// systemID / unwired runner; everything else flows through
// PingResult.Status (success / failure / no_accepted_host_key /
// missing_credentials).
func (r *Runner) Ping(ctx context.Context, systemID string) (PingResult, error) {
	if strings.TrimSpace(systemID) == "" {
		return PingResult{}, fmt.Errorf("%w: system_id required", ErrInvalidRequest)
	}
	if r.Executor == nil || r.Systems == nil || r.Credentials == nil ||
		r.HostKeys == nil || r.Vault == nil {
		return PingResult{}, fmt.Errorf("%w: runner is not fully wired", ErrInvalidRequest)
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}

	sys, err := r.Systems.Get(systemID)
	if err != nil {
		if errors.Is(err, systems.ErrNotFound) {
			return PingResult{}, fmt.Errorf("%w: system %q not found", ErrInvalidRequest, systemID)
		}
		return PingResult{}, fmt.Errorf("ansible: load system: %w", err)
	}

	result := PingResult{
		SystemID:   sys.ID,
		SystemName: sys.Name,
		StartedAt:  now().UTC(),
	}

	resolved, credsOK := r.resolveCredentials(sys)
	if !credsOK {
		result.FinishedAt = now().UTC()
		result.Status = RunMissingCreds
		result.Reason = "no credentials resolve for this system"
		r.logPing(ctx, sys, result)
		return result, nil
	}

	accepted, err := r.HostKeys.AcceptedFor(sys.ID)
	if err != nil {
		return PingResult{}, fmt.Errorf("ansible: load host keys: %w", err)
	}
	if len(accepted) == 0 {
		// Same posture as Run: capture what's offered as pending
		// before bailing so the operator's banner reflects reality.
		if err := r.scanAndRecord(ctx, sys); err != nil {
			slog.Warn("ansible: ping keyscan bailout", "err", err, "system_id", sys.ID)
		}
		result.FinishedAt = now().UTC()
		result.Status = RunNoAcceptedHostKey
		result.Reason = "no accepted host key for this system"
		r.logPing(ctx, sys, result)
		return result, nil
	}

	tmpDir, err := os.MkdirTemp("", "sw-ping-")
	if err != nil {
		return PingResult{}, fmt.Errorf("ansible: mkdir tmp: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(tmpDir); rmErr != nil {
			slog.Warn("ansible: ping tmp cleanup", "err", rmErr, "dir", tmpDir)
		}
	}()

	keyPath, err := r.writePrivateKey(tmpDir, resolved.PrivateKey)
	if err != nil {
		return PingResult{}, err
	}
	knownHostsPath, err := writeKnownHosts(tmpDir, sys.Hostname, accepted)
	if err != nil {
		return PingResult{}, err
	}
	inventoryPath, err := writeInventory(tmpDir, sys, resolved.AnsibleUser)
	if err != nil {
		return PingResult{}, err
	}

	args := []string{
		sys.Hostname,
		"-i", inventoryPath,
		"--private-key", keyPath,
		"-u", resolved.AnsibleUser,
		"-m", "ping",
	}
	env := append(os.Environ(),
		"ANSIBLE_HOST_KEY_CHECKING=True",
		"ANSIBLE_SSH_COMMON_ARGS=-o UserKnownHostsFile="+knownHostsPath+
			" -o StrictHostKeyChecking=yes"+
			" -o ConnectTimeout=10",
	)

	stdout, stderr, exitCode, execErr := r.Executor.Run(ctx, AnsibleAdHocBinary, args, env, nil)
	result.FinishedAt = now().UTC()
	result.Stdout = stdout
	result.Stderr = stderr
	result.ExitCode = exitCode

	if execErr != nil {
		result.Status = RunFailure
		result.Reason = "executor error: " + execErr.Error()
		if len(result.Stderr) == 0 {
			result.Stderr = []byte(execErr.Error())
		}
		r.logPing(ctx, sys, result)
		return result, nil
	}

	if exitCode == 0 && bytes.Contains(stdout, []byte(pongMarker)) {
		result.Status = RunSuccess
		result.Reason = "pong"
		r.logPing(ctx, sys, result)
		return result, nil
	}

	if looksLikeHostKeyMismatch(stderr) {
		if err := r.scanAndRecord(ctx, sys); err != nil {
			slog.Warn("ansible: ping keyscan mismatch capture", "err", err, "system_id", sys.ID)
		}
		result.Status = RunHostKeyMismatch
		result.Reason = "host key mismatch"
		r.logPing(ctx, sys, result)
		return result, nil
	}
	result.Status = RunFailure
	if exitCode == 0 {
		// Exit 0 but no pong marker — module ran but produced
		// unexpected output (theoretically impossible for builtin
		// ping; defensive).
		result.Reason = "ansible exited 0 but did not return pong"
	} else {
		result.Reason = fmt.Sprintf("ansible exited %d", exitCode)
	}
	r.logPing(ctx, sys, result)
	return result, nil
}

// logPing emits one `system.connection.test` audit row per Ping
// invocation. Audit action is distinct from `ansible.run.*` because
// this is the operator-clicked health check, not a scheduled
// playbook run — readers want to filter them separately.
func (r *Runner) logPing(ctx context.Context, sys systems.System, result PingResult) {
	outcome := audit.Success
	if result.Status != RunSuccess {
		outcome = audit.Failure
	}
	r.logAudit(ctx, audit.Event{
		Action:      "system.connection.test",
		Outcome:     outcome,
		TargetKind:  "system",
		TargetID:    sys.ID,
		TargetLabel: sys.Name,
		Detail: audit.Detail{
			"status":      string(result.Status),
			"exit_code":   result.ExitCode,
			"duration_ms": result.FinishedAt.Sub(result.StartedAt).Milliseconds(),
			"reason":      result.Reason,
		},
	})
}

func (r *Runner) validate(req Request) error {
	if strings.TrimSpace(req.SystemID) == "" {
		return fmt.Errorf("%w: system_id required", ErrInvalidRequest)
	}
	if strings.TrimSpace(req.PlaybookPath) == "" {
		return fmt.Errorf("%w: playbook_path required", ErrInvalidRequest)
	}
	if _, err := os.Stat(req.PlaybookPath); err != nil {
		return fmt.Errorf("%w: playbook %q: %v", ErrInvalidRequest, req.PlaybookPath, err)
	}
	if r.Executor == nil || r.Systems == nil || r.Credentials == nil ||
		r.HostKeys == nil || r.Vault == nil {
		return fmt.Errorf("%w: runner is not fully wired", ErrInvalidRequest)
	}
	return nil
}

// resolveCredentials runs the credentials.Resolve walk and opens
// the sealed private key with the runner's vault. Returns
// (Resolved, true) on success or (zero, false) when anything in
// the chain is missing — the caller surfaces that as
// RunMissingCreds.
func (r *Runner) resolveCredentials(sys systems.System) (resolvedCreds, bool) {
	res, err := credentials.Resolve(r.Credentials, sys.ID, sys.GroupID)
	if err != nil {
		return resolvedCreds{}, false
	}
	plain, err := credentials.OpenWith(r.Vault, res.PrivateKey)
	if err != nil {
		return resolvedCreds{}, false
	}
	return resolvedCreds{
		AnsibleUser: res.AnsibleUser,
		PrivateKey:  plain,
	}, true
}

// resolvedCreds is the runner-internal projection of
// credentials.Resolved with the private key already opened.
type resolvedCreds struct {
	AnsibleUser string
	PrivateKey  []byte
}

// scanAndRecord delegates to hostkeys.Scan. The runner doesn't own
// the keyscan logic itself — keeping it in hostkeys lets the
// host-keys HTTP handler share one implementation for the
// "capture host keys now" button without cycling back through
// this package.
func (r *Runner) scanAndRecord(ctx context.Context, sys systems.System) error {
	_, err := hostkeys.Scan(ctx, r.Executor, r.HostKeys, r.Audit, sys)
	return err
}

// writePrivateKey writes the unsealed PEM to a 0600 file inside
// tmpDir. Returns the path. Caller's defer-RemoveAll handles
// cleanup.
func (r *Runner) writePrivateKey(tmpDir string, pem []byte) (string, error) {
	path := filepath.Join(tmpDir, "id")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		return "", fmt.Errorf("ansible: write private key: %w", err)
	}
	return path, nil
}

// writeKnownHosts emits one line per accepted host key in the
// classic format: "<hostname> <algorithm> <pubkey>". The hostname
// is the system's connection target — wildcards, IPs, and HashKnownHosts
// are deliberately not used because the file is per-run and never
// shared across systems.
func writeKnownHosts(tmpDir, hostname string, accepted []hostkeys.HostKey) (string, error) {
	var b strings.Builder
	for _, k := range accepted {
		b.WriteString(hostname)
		b.WriteByte(' ')
		b.WriteString(k.Algorithm)
		b.WriteByte(' ')
		b.WriteString(k.PublicKey)
		b.WriteByte('\n')
	}
	path := filepath.Join(tmpDir, "known_hosts")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("ansible: write known_hosts: %w", err)
	}
	return path, nil
}

// writeInventory writes a minimal INI inventory with one host and
// the resolved ansible user pinned via host_vars. ansible-playbook
// needs the `,` trailing form on -i to accept a host literal, but
// a real file is friendlier for diffs and tests.
func writeInventory(tmpDir string, sys systems.System, ansibleUser string) (string, error) {
	hostLine := sys.Hostname
	if ansibleUser != "" {
		hostLine += " ansible_user=" + ansibleUser
	}
	// Quote IP-style hostnames defensively — ansible's INI parser
	// is happy with bare IPs but a future change to the hostname
	// format (FQDN with ":port"?) could confuse it; explicit is
	// cheaper than debugging it later.
	if strings.ContainsAny(sys.Hostname, " \t") || net.ParseIP(sys.Hostname) != nil {
		// no quoting needed for IPs in INI form; left as-is.
		_ = hostLine
	}
	contents := "[targets]\n" + hostLine + "\n"
	path := filepath.Join(tmpDir, "inventory.ini")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		return "", fmt.Errorf("ansible: write inventory: %w", err)
	}
	return path, nil
}

// writeExtraVars marshals vars to JSON (also valid YAML) and writes
// to a temp file so ansible-playbook can ingest it via @-syntax
// without command-line quoting.
func writeExtraVars(tmpDir string, vars map[string]any) (string, error) {
	body, err := json.Marshal(vars)
	if err != nil {
		return "", fmt.Errorf("ansible: marshal extra vars: %w", err)
	}
	path := filepath.Join(tmpDir, "extra-vars.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", fmt.Errorf("ansible: write extra vars: %w", err)
	}
	return path, nil
}

// looksLikeHostKeyMismatch returns true when stderr contains a
// recognizable ssh host-key-failure marker. We deliberately keep
// the matcher coarse — any of the well-known OpenSSH phrases
// triggers a rescan, which is the right move whether the mismatch
// is "key changed" or "no key on file at all."
func looksLikeHostKeyMismatch(stderr []byte) bool {
	s := string(stderr)
	markers := []string{
		"REMOTE HOST IDENTIFICATION HAS CHANGED",
		"Host key verification failed",
		"is unknown for this host",
	}
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// logStart emits ansible.run.start. The audit row's ID equals the
// run ID so the complete row can reference it via detail.parent_id
// — same trick the secret-rotate plumbing uses.
func (r *Runner) logStart(ctx context.Context, run Run, ansibleUser string) {
	r.logAudit(ctx, audit.Event{
		ID:          run.ID,
		Action:      "ansible.run.start",
		Outcome:     audit.Success,
		TargetKind:  "system",
		TargetID:    run.SystemID,
		TargetLabel: run.SystemName,
		Detail: audit.Detail{
			"run_id":       run.ID,
			"playbook":     run.Playbook,
			"ansible_user": ansibleUser,
		},
	})
}

// logComplete emits ansible.run.complete. note is empty for the
// success path; on every failure status it carries a short
// human-readable reason for the audit reader.
func (r *Runner) logComplete(ctx context.Context, run Run, note string) {
	outcome := audit.Success
	if run.Status != RunSuccess {
		outcome = audit.Failure
	}
	detail := audit.Detail{
		"parent_id":   run.ID,
		"status":      string(run.Status),
		"exit_code":   run.ExitCode,
		"duration_ms": run.FinishedAt.Sub(run.StartedAt).Milliseconds(),
	}
	if note != "" {
		detail["note"] = note
	}
	r.logAudit(ctx, audit.Event{
		Action:      "ansible.run.complete",
		Outcome:     outcome,
		TargetKind:  "system",
		TargetID:    run.SystemID,
		TargetLabel: run.SystemName,
		Detail:      detail,
	})
}

func (r *Runner) logAudit(ctx context.Context, e audit.Event) {
	if r.Audit == nil {
		return
	}
	if err := r.Audit.Log(ctx, e); err != nil {
		slog.Error("ansible audit log", "err", err, "action", e.Action)
	}
}
