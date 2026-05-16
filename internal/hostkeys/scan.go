// SPDX-License-Identifier: Apache-2.0

package hostkeys

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/systems"
)

// SSHKeyscanBinary is the executable Scan spawns. Exposed so tests
// (and a deployment-specific override) can swap it. Defaults to
// "ssh-keyscan" — assumed on PATH inside the container.
var SSHKeyscanBinary = "ssh-keyscan"

// SSHKeyscanAlgorithms is the `-t` argument passed to ssh-keyscan.
// ed25519 first (modern hosts), then ECDSA and RSA for older
// OpenSSH installs. Order doesn't matter for storage — keys are
// indexed by algorithm.
const SSHKeyscanAlgorithms = "ssh-ed25519,ecdsa-sha2-nistp256,ssh-rsa"

// SSHKeyscanTimeoutSeconds is the per-connection timeout passed
// via `-T`. Pinned here so behaviour is identical regardless of
// ssh-keyscan's compiled-in default.
const SSHKeyscanTimeoutSeconds = 5

// Executor is the minimal seam Scan uses to invoke ssh-keyscan.
// Internal/ansible.Executor has the same shape and satisfies this
// interface implicitly — production wires the same instance into
// both packages.
type Executor interface {
	Run(ctx context.Context, cmd string, args []string, env []string, stdin []byte) (stdout, stderr []byte, exitCode int, err error)
}

// OfferedKey is one entry from ssh-keyscan's output. Exposed for
// callers (the ansible Runner) that want to inspect what was
// found without going through Scan's RecordPending path.
type OfferedKey struct {
	Algorithm   string
	PublicKey   string
	Fingerprint string
}

// Scan invokes ssh-keyscan against sys.Hostname, upserts each
// offered key into store as `pending`, and emits one
// `system.host_key.pending` audit row per recorded key. Returns
// the host-key rows that landed (with their store-assigned IDs)
// so the caller can render the results without re-listing.
//
// auditStore may be nil — used by tests that don't care about
// audit emissions. Errors from RecordPending are logged but do
// not short-circuit the loop; one bad row should not lose the
// rest.
func Scan(ctx context.Context, exec Executor, store Store, auditStore *audit.Store, sys systems.System) ([]HostKey, error) {
	if exec == nil {
		return nil, fmt.Errorf("hostkeys: executor is nil")
	}
	args := []string{
		"-T", strconv.Itoa(SSHKeyscanTimeoutSeconds),
		"-t", SSHKeyscanAlgorithms,
		sys.Hostname,
	}
	stdout, _, exitCode, err := exec.Run(ctx, SSHKeyscanBinary, args, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("hostkeys: ssh-keyscan: %w", err)
	}
	if exitCode != 0 && len(stdout) == 0 {
		return nil, fmt.Errorf("hostkeys: ssh-keyscan exit %d with no output", exitCode)
	}
	offered, err := ParseKeyscan(stdout)
	if err != nil {
		return nil, err
	}
	out := make([]HostKey, 0, len(offered))
	for _, k := range offered {
		hk, err := store.RecordPending(sys.ID, k.Algorithm, k.PublicKey, k.Fingerprint)
		if err != nil {
			slog.Error("hostkeys: record pending", "err", err, "system_id", sys.ID)
			continue
		}
		out = append(out, hk)
		if auditStore != nil {
			if err := auditStore.Log(ctx, audit.Event{
				Action:      "system.host_key.pending",
				Outcome:     audit.Success,
				TargetKind:  "system",
				TargetID:    sys.ID,
				TargetLabel: sys.Name,
				Detail: audit.Detail{
					"algorithm":   hk.Algorithm,
					"fingerprint": hk.Fingerprint,
				},
			}); err != nil {
				slog.Error("hostkeys: audit log", "err", err, "action", "system.host_key.pending")
			}
		}
	}
	return out, nil
}

// ParseKeyscan splits ssh-keyscan output into OfferedKey records.
// Comments (lines starting with `#`) are dropped — ssh-keyscan
// prefixes its diagnostic notes that way. Lines that don't parse
// as authorized_keys are skipped silently rather than failing the
// whole scan; partial output is better than no output when one
// algorithm misbehaves.
func ParseKeyscan(output []byte) ([]OfferedKey, error) {
	out := []OfferedKey{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// ssh-keyscan emits "<hostname> <algo> <base64-blob>".
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		algo := fields[1]
		blob := fields[2]
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(algo + " " + blob))
		if err != nil {
			continue
		}
		out = append(out, OfferedKey{
			Algorithm:   algo,
			PublicKey:   blob,
			Fingerprint: ssh.FingerprintSHA256(pub),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("hostkeys: scan ssh-keyscan output: %w", err)
	}
	return out, nil
}
