// SPDX-License-Identifier: Apache-2.0

// Package hostkeys is the trust-on-first-use substrate for SSH host
// keys. It records the keys each managed system has presented across
// connection attempts and gates ansible runs on operator acceptance.
// Design and discipline: research/host-keys.md.
//
// The schema invariant is that a given (system_id, state, algorithm)
// triple is unique — a system has at most one accepted key and at
// most one pending key per SSH host-key algorithm. The exec wrapper
// (internal/ansible, Phase 4b) calls RecordPending after a
// host-key-mismatch run; the HTTP handler exposes accept/reject for
// the operator-facing banner.
package hostkeys

import (
	"errors"
	"time"
)

// State is the lifecycle column. A pending row exists because the
// exec wrapper saw a key the operator has not yet approved; an
// accepted row exists because an operator clicked Accept. The
// `system.host_key.replace` audit event records the transition when
// a new pending row replaces an existing accepted row for the same
// algorithm.
type State string

// State values stored in system_host_keys.state.
const (
	StatePending  State = "pending"
	StateAccepted State = "accepted"
)

// IsValid reports whether s is one of the two known states.
func (s State) IsValid() bool {
	return s == StatePending || s == StateAccepted
}

// HostKey is one row from system_host_keys. PublicKey is the
// authorized_keys-style body (just the base64 blob — no leading
// algorithm or trailing comment); Algorithm carries the algorithm
// string ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", etc.).
// Fingerprint is the SHA256 the UI displays.
type HostKey struct {
	ID          string
	SystemID    string
	State       State
	Algorithm   string
	PublicKey   string
	Fingerprint string
	FirstSeenAt time.Time
	AcceptedAt  *time.Time
	AcceptedBy  string
}

// Sentinel errors returned by the hostkeys store and handler.
var (
	ErrNotFound          = errors.New("hostkeys: row not found")
	ErrInvalid           = errors.New("hostkeys: invalid input")
	ErrFingerprintStale  = errors.New("hostkeys: fingerprint does not match the pending row")
	ErrNoAcceptedHostKey = errors.New("hostkeys: no accepted host key for this system")
)
