// SPDX-License-Identifier: Apache-2.0

// Package ansible is the thin substrate that invokes ansible-playbook
// against managed systems. It owns the wire-up between
// internal/credentials (which authenticates SW to the host),
// internal/hostkeys (which authenticates the host to SW), and the
// ansible-playbook binary on the container's PATH.
//
// The package is deliberately small. It does not own playbooks — the
// future updater substrate writes those to disk and hands the path
// to Run(). It does not own scheduling — that's a separate concern
// for the scheduler when it lands. What it owns is one cycle:
// resolve creds, check host-key trust, materialize per-run temp
// files, invoke ansible-playbook, emit audit rows.
//
// Design: research/ansible-auth.md and research/host-keys.md.
package ansible

import (
	"errors"
	"time"
)

// RunStatus is the closed enum of outcomes Run returns. The audit
// row's detail.status takes the same values so an operator filtering
// the log can see exactly why a run did not succeed.
type RunStatus string

// Run statuses. "success" means ansible-playbook exited 0;
// "failure" covers any other ansible-side failure (task error,
// unreachable when host keys did match, etc.); the host-key and
// credential statuses bail out before ansible is ever invoked, or
// re-bail after a connection-time failure.
const (
	RunSuccess           RunStatus = "success"
	RunFailure           RunStatus = "failure"
	RunHostKeyMismatch   RunStatus = "host_key_mismatch"
	RunNoAcceptedHostKey RunStatus = "no_accepted_host_key"
	RunMissingCreds      RunStatus = "missing_credentials"
)

// Run is the result of one invocation. The Stdout/Stderr buffers are
// what ansible-playbook produced — callers can stream them into the
// future updater_runs table or surface tail lines to the UI.
type Run struct {
	ID         string
	SystemID   string
	SystemName string
	Playbook   string
	StartedAt  time.Time
	FinishedAt time.Time
	Status     RunStatus
	ExitCode   int
	Stdout     []byte
	Stderr     []byte
}

// Request is the shape Run accepts. PlaybookPath must exist on the
// filesystem when Run is called — the caller (future updater
// substrate) writes the playbook to a temp dir first. Vars is
// marshaled to JSON and handed to ansible-playbook as
// --extra-vars '@<file>' so escaping stays sane.
type Request struct {
	SystemID     string
	PlaybookPath string
	Vars         map[string]any
}

// Sentinel errors returned by Run. Callers compare with errors.Is.
// ErrInvalidRequest is for malformed inputs (empty SystemID, missing
// playbook); the credential / host-key paths surface their own
// statuses through Run.Status instead of errors so the caller can
// keep one happy-path branch.
var (
	ErrInvalidRequest = errors.New("ansible: invalid request")
)
