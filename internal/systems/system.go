// SPDX-License-Identifier: AGPL-3.0-or-later

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

var (
	ErrNotFound = errors.New("system not found")
	ErrInvalid  = errors.New("invalid system")
)

// Status reflects the most recent probe outcome for a system.
type Status string

const (
	StatusUnprobed    Status = "unprobed"
	StatusReachable   Status = "reachable"
	StatusUnreachable Status = "unreachable"
)

// Host is a managed system in the fleet.
type System struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Hostname  string     `json:"hostname"`
	CreatedAt time.Time  `json:"createdAt"`
	Status    Status     `json:"status"`
	LastSeen  *time.Time `json:"lastSeen,omitempty"`
}

// HostInput is the user-supplied subset of a Host accepted on create.
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
