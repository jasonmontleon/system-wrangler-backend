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
	// PendingPackages is the union of package names the system's
	// enabled updaters reported pending on their most recent check.
	// Surfaced here so the systems list can render a hover-tooltip
	// without an N+1 fetch per row. Empty when no check has run.
	PendingPackages []string `json:"pendingPackages,omitempty"`
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
}

// Stats is the per-system updater aggregate the systems handler
// merges into each row before serialization. The producer lives
// outside this package (the updater store) and is injected via
// Handler.SystemStats so systems doesn't depend on updaters.
type Stats struct {
	LastCheckedAt   *time.Time
	PendingUpdates  int
	PendingPackages []string
	LastRunFailed   bool
	LastRunReason   string
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
