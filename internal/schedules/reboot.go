// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/systems"
)

// AnsibleRunner is the slice of *ansible.Runner the reboot path
// needs. Defined here so tests can inject a fake.
type AnsibleRunner interface {
	Run(ctx context.Context, req ansible.Request) (ansible.Run, error)
}

// RebootClearer clears the host's reboot_required_at flag after a
// successful reboot. systems.SQLiteStore satisfies it.
type RebootClearer interface {
	ClearRebootRequired(systemID string) error
}

// rebootPlaybook returns the YAML body to run against the host. The
// Unix and Windows shapes are distinct enough — different module
// names, different default timeouts — that branching on IsWindows up
// front beats a `when:` guard inside a unified playbook.
func rebootPlaybook(isWindows bool) []byte {
	if isWindows {
		return []byte(`---
- hosts: all
  gather_facts: false
  tasks:
    - name: Reboot Windows host and wait for it to return
      ansible.windows.win_reboot:
        msg: System Wrangler scheduled reboot
        reboot_timeout: 600
`)
	}
	return []byte(`---
- hosts: all
  gather_facts: false
  become: true
  tasks:
    - name: Reboot host and wait for it to return
      ansible.builtin.reboot:
        msg: System Wrangler scheduled reboot
        reboot_timeout: 600
`)
}

// RebootIfRequired reboots `systemID` when its hosts.reboot_required_at
// flag is set, waits for it to come back, then clears the flag.
// Returns (rebooted bool, error). Callers tally a "reboot attempted
// but not needed" as a no-op; only true failures bubble back.
func RebootIfRequired(
	ctx context.Context,
	systemID string,
	sysStore SystemStore,
	clearer RebootClearer,
	runner AnsibleRunner,
) (bool, error) {
	sys, err := sysStore.Get(systemID)
	if err != nil {
		return false, fmt.Errorf("schedules: reboot lookup: %w", err)
	}
	if sys.RebootRequiredAt == nil {
		return false, nil
	}
	path, cleanup, err := writeRebootPlaybook(rebootPlaybook(sys.IsWindows))
	if err != nil {
		return false, err
	}
	defer cleanup()
	run, err := runner.Run(ctx, ansible.Request{
		SystemID:     systemID,
		PlaybookPath: path,
		OmitAudit:    true,
	})
	if err != nil {
		return false, fmt.Errorf("schedules: reboot run: %w", err)
	}
	if run.Status != ansible.RunSuccess {
		return false, fmt.Errorf("schedules: reboot did not succeed: %s", run.Status)
	}
	if err := clearer.ClearRebootRequired(systemID); err != nil {
		// The reboot worked; flag clear failed. The next probe will
		// re-stamp it if the kernel is still waiting on a restart,
		// so this is annoying but not catastrophic.
		return true, fmt.Errorf("schedules: clear reboot flag: %w", err)
	}
	return true, nil
}

// writeRebootPlaybook mirrors updaters.writePlaybook but lives here
// so the schedules package doesn't have to import an internal helper
// from updaters. A tiny duplication beats a cross-package coupling
// for a 15-line utility.
func writeRebootPlaybook(body []byte) (string, func(), error) {
	dir, err := os.MkdirTemp("", "sw-schedule-reboot-")
	if err != nil {
		return "", func() {}, fmt.Errorf("schedules: mkdir tmp: %w", err)
	}
	cleanup := func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("schedules: reboot temp dir cleanup", "err", rmErr, "dir", dir)
		}
	}
	path := filepath.Join(dir, "reboot.yml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("schedules: write reboot playbook: %w", err)
	}
	return path, cleanup, nil
}

// ErrRebootStoreMissing is the sentinel surfaced when RebootIfRequired
// is called without a systems store wired. Distinct from any I/O error
// the wired store might emit.
var ErrRebootStoreMissing = errors.New("schedules: systems store not configured for reboot")

// Compile-time check: *systems.SQLiteStore must satisfy RebootClearer.
// Sits here (not in main) so a future refactor of the systems package
// can't silently break the contract.
var _ RebootClearer = (*systems.SQLiteStore)(nil)
