// SPDX-License-Identifier: Apache-2.0

// Package systems tracks the fleet of managed systems.
package systems

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Maximum lengths are conservative; tighten only if a concrete need appears.
const maxFieldLen = 255

// Sentinel errors returned by the systems store and handler.
var (
	ErrNotFound = errors.New("system not found")
	ErrInvalid  = errors.New("invalid system")
)

// Status reflects the most recent probe outcome for a system.
type Status string

// Probe-result statuses persisted on a System.
const (
	StatusUnprobed    Status = "unprobed"
	StatusReachable   Status = "reachable"
	StatusUnreachable Status = "unreachable"
)

// System is a managed host in the fleet. GroupID is nil for systems that
// are not yet assigned to a system group; resolving the group's name is
// the frontend's job (it already fetches /api/groups) so that systems
// doesn't depend on the groups package.
//
// LastCheckedAt and PendingUpdates are populated at handler time by an
// injected stats hook (wired in cmd/server/main.go against the updater
// store). The fields are pointer-valued so the JSON "no data yet" shape
// is distinguishable from "checked, zero pending."
type System struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Hostname       string     `json:"hostname"`
	CreatedAt      time.Time  `json:"createdAt"`
	Status         Status     `json:"status"`
	LastSeen       *time.Time `json:"lastSeen,omitempty"`
	GroupID        *string    `json:"groupId,omitempty"`
	LastCheckedAt  *time.Time `json:"lastCheckedAt,omitempty"`
	PendingUpdates *int       `json:"pendingUpdates,omitempty"`
	// PendingPackages is the union of packages the system's enabled
	// updaters reported pending on their most recent check, each
	// with the installed and available version strings the
	// underlying package manager surfaced. Empty when no check has
	// run. Surfaced here so the systems list can render a
	// hover-tooltip without an N+1 fetch per row.
	PendingPackages []PendingPackage `json:"pendingPackages,omitempty"`
	// LastRunFailed is true when the most recent terminated updater
	// run (any kind: inspect/check/apply) exited non-zero. The SPA
	// uses this to flip the row health glyph to red even when the
	// system probes reachable.
	LastRunFailed bool `json:"lastRunFailed,omitempty"`
	// LastRunReason is a short, operator-readable summary of the
	// failure — e.g. "apply exit 2". Empty when no run has failed
	// yet; the SPA pairs it with LastRunFailed for the "Needs
	// Attention" line on the detail page.
	LastRunReason string `json:"lastRunReason,omitempty"`
	// IsWindows is the operator-declared platform flag. False means the
	// host is treated as Unix-like (Linux/macOS/BSD) — Ansible probes use
	// `command -v`, ad-hoc Ping uses `-m ping`. True swaps both halves to
	// the PowerShell-on-OpenSSH path (`ansible_shell_type=powershell` in
	// inventory, `where.exe` probes, `-m ansible.windows.win_ping`).
	IsWindows bool `json:"isWindows,omitempty"`
	// Running is true when an updater (inspect / check / apply) is
	// currently in flight against this system. Seeded by the
	// systems-stats hook from system_action_locks so the SPA can keep
	// a row's spinner lit across page navigation.
	Running bool `json:"running,omitempty"`
}

// PendingPackage is the systems-package mirror of the updaters
// PendingPackage struct. We don't import updaters here so systems
// stays the lower layer in the dependency graph; the wiring layer
// (cmd/server) converts between the two shapes.
type PendingPackage struct {
	Name       string `json:"name"`
	OldVersion string `json:"oldVersion"`
	NewVersion string `json:"newVersion"`
}

// Stats is the per-system updater aggregate the systems handler
// merges into each row before serialization. The producer lives
// outside this package (the updater store) and is injected via
// Handler.SystemStats so systems doesn't depend on updaters.
type Stats struct {
	LastCheckedAt   *time.Time
	PendingUpdates  int
	PendingPackages []PendingPackage
	LastRunFailed   bool
	LastRunReason   string
	Running         bool
}

// SystemInput is the user-supplied subset of a System accepted on create.
type SystemInput struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
}

// Validate returns ErrInvalid wrapped with a field-specific message if the
// input is unusable. Callers should treat any error as a 400-level failure.
func (in SystemInput) Validate() error {
	name := strings.TrimSpace(in.Name)
	host := strings.TrimSpace(in.Hostname)
	switch {
	case name == "":
		return fmt.Errorf("%w: name is required", ErrInvalid)
	case len(name) > maxFieldLen:
		return fmt.Errorf("%w: name exceeds %d chars", ErrInvalid, maxFieldLen)
	case host == "":
		return fmt.Errorf("%w: hostname is required", ErrInvalid)
	case len(host) > maxFieldLen:
		return fmt.Errorf("%w: hostname exceeds %d chars", ErrInvalid, maxFieldLen)
	}
	return nil
}

// newUUID returns a RFC 4122 v4 UUID. crypto/rand.Read on Linux reads from
// getrandom(2) and does not return an error in practice; a panic here would
// indicate a broken kernel.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("systems: rand.Read: %w", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
