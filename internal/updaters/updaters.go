// SPDX-License-Identifier: Apache-2.0

// Package updaters owns the substrate for "make this remote system
// install its pending updates." Two-playbook-per-updater shape: each
// updater registers a check playbook (read-only "what's pending")
// and an apply playbook (mutate the host). The runtime registry
// unions code-registered builtins (embedded via go:embed) with custom
// updaters stored in SQLite. Design and discipline:
// research/updaters.md.
//
// The package is deliberately runner-agnostic — it holds types, the
// SQLite store, and the registry. The actual ansible orchestration
// lives in Runner (sibling file runner.go in this same package);
// HTTP wiring lives in handler.go.
package updaters

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Source classifies a definition as code-registered (builtin) or
// DB-persisted (custom). Stored implicitly via the ID prefix; the
// registry rejects any custom row whose ID starts with "builtin." and
// any builtin whose ID doesn't.
type Source string

// Source values. SourceBuiltin updaters ship in the Go binary;
// SourceCustom updaters are Global-Admin-managed rows in
// updater_definitions.
const (
	SourceBuiltin Source = "builtin"
	SourceCustom  Source = "custom"
)

// PrefixBuiltin and PrefixCustom reserve the two id namespaces. The
// registry refuses any operation that violates the matching
// invariant.
const (
	PrefixBuiltin = "builtin."
	PrefixCustom  = "custom."
)

// MaxPlaybookBytes caps individual playbook bodies. 64 KB is plenty
// for every updater on the roadmap (the dnf builtin sits in the
// 1–2 KB range); the cap defends the handler from a runaway paste.
const MaxPlaybookBytes = 64 * 1024

// Definition is a single registered updater. CheckPlaybook and
// ApplyPlaybook are raw YAML bodies; the runner writes them to a
// temp file at run time. DetectBinary is the executable name the
// inspection playbook checks for (`command -v <this>` on Unix
// hosts, `where.exe <this>` on Windows hosts).
//
// CheckOnly marks an updater that surfaces pending changes but
// must never auto-apply — firmware updates being the driving case.
// When set, ApplyPlaybook must be empty; the runner refuses Apply
// with ErrCheckOnly and the SPA hides the per-row Update action.
type Definition struct {
	ID            string
	Source        Source
	DisplayName   string
	Description   string
	DetectBinary  string
	CheckPlaybook []byte
	ApplyPlaybook []byte
	CheckOnly     bool
	CreatedBy     string    // empty for builtins
	CreatedAt     time.Time // zero for builtins
	UpdatedAt     time.Time // zero for builtins
	DeletedAt     *time.Time
}

// IsDeleted reports whether d carries a soft-delete tombstone.
// Builtins never have one; deleted custom definitions are still
// returned by audit / run-history lookups so the name resolves.
func (d Definition) IsDeleted() bool {
	return d.DeletedAt != nil && !d.DeletedAt.IsZero()
}

// detectBinaryPattern restricts DetectBinary to a narrow charset so
// the inspection playbook can interpolate the name into a shell
// command without escaping concerns. Real package-manager binaries
// (dnf, apt, pacman, brew, flatpak, fwupdmgr, choco) all fit.
var detectBinaryPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Validate enforces the input-side invariants for custom updaters.
// Builtin definitions skip Validate — they're frozen at compile
// time. ID conformance is checked separately by the registry
// because the rule differs between sources.
func (d Definition) Validate() error {
	d.DisplayName = strings.TrimSpace(d.DisplayName)
	d.DetectBinary = strings.TrimSpace(d.DetectBinary)
	if d.DisplayName == "" {
		return errors.New("updaters: display_name required")
	}
	if d.DetectBinary == "" {
		return errors.New("updaters: detect_binary required")
	}
	if !detectBinaryPattern.MatchString(d.DetectBinary) {
		return errors.New("updaters: detect_binary must match [A-Za-z0-9._-]{1,64}")
	}
	if len(d.CheckPlaybook) == 0 {
		return errors.New("updaters: check_playbook required")
	}
	if d.CheckOnly {
		if len(d.ApplyPlaybook) != 0 {
			return errors.New("updaters: check_only updaters must not declare an apply_playbook")
		}
	} else {
		if len(d.ApplyPlaybook) == 0 {
			return errors.New("updaters: apply_playbook required")
		}
	}
	if len(d.CheckPlaybook) > MaxPlaybookBytes {
		return errors.New("updaters: check_playbook exceeds 64 KB cap")
	}
	if len(d.ApplyPlaybook) > MaxPlaybookBytes {
		return errors.New("updaters: apply_playbook exceeds 64 KB cap")
	}
	return nil
}

// PendingPackage is one entry surfaced by a check playbook's
// SW_PENDING_PACKAGE markers. Name is the package identifier; the
// version fields are the installed (OldVersion) and available
// (NewVersion) strings as the package manager reports them. Either
// version may be empty — flatpak and snap can only cheaply surface
// the new version, and custom updaters that emit only a name are
// accepted as `{Name: name}` (both versions empty).
type PendingPackage struct {
	Name       string `json:"name"`
	OldVersion string `json:"oldVersion"`
	NewVersion string `json:"newVersion"`
}

// Availability is one row from system_updaters — "as of the last
// inspection, system X has updater Y detected." Absence of a row
// means "not detected" (or "never inspected" — distinguished by the
// system's last-inspection timestamp at the page level).
//
// Enabled is the operator's per-system toggle: a fan-out check or
// apply only fires the updaters that are detected AND enabled.
// Defaults to true so a freshly-inspected updater is active without
// extra ceremony.
type Availability struct {
	SystemID   string
	UpdaterID  string
	Enabled    bool
	LastSeenAt *time.Time
	// PendingPackages is the JSON-decoded list the latest check run
	// reported as pending. Empty when the updater's check playbook
	// does not emit SW_PENDING_PACKAGE markers, or when no check has
	// ever run.
	PendingPackages []PendingPackage
}

// RunKind classifies an updater_runs row. Inspect is reserved for
// the per-system "what's installed here" sweep; check and apply
// match the per-updater endpoints.
type RunKind string

// RunKind values stored in updater_runs.kind.
const (
	RunKindInspect RunKind = "inspect"
	RunKindCheck   RunKind = "check"
	RunKindApply   RunKind = "apply"
)

// IsValid reports whether k is one of the known kinds.
func (k RunKind) IsValid() bool {
	return k == RunKindInspect || k == RunKindCheck || k == RunKindApply
}

// Run is one row in updater_runs. UpdaterID is empty when Kind is
// inspect (the sweep covers every registered updater at once);
// non-empty for check and apply. LogTail is the trailing ~12 KB of
// the ansible stdout/stderr stream; the full output is not stored
// — re-run the operation if the tail is not enough. AffectedCount
// is the SW_AFFECTED_COUNT marker captured at run finish; the
// systems list aggregates this across the latest check run per
// updater to surface "Updates Available" per host.
type Run struct {
	ID            string
	SystemID      string
	UpdaterID     string // "" for inspect
	Kind          RunKind
	StartedAt     time.Time
	FinishedAt    *time.Time
	ExitCode      *int
	AffectedCount int
	ActorID       string
	PlaybookSHA   string // SHA-256 of the body that ran (hex)
	LogTail       string
}

// SystemStats is the per-system aggregate that powers the Systems
// list's new "Last checked" and "Updates available" columns. Pulled
// in one batch query from SystemStatsAll so the systems handler
// doesn't N+1 against updater_runs.
type SystemStats struct {
	// LastCheckedAt is the timestamp of the most recent check run
	// started against this system, across every updater. Nil when
	// no check run exists — the SPA renders that as "Never".
	LastCheckedAt *time.Time
	// PendingUpdates sums affected_count from the latest check run
	// per (system, updater). Zero when no check has ever run, or
	// when every updater reported zero pending changes; the SPA
	// distinguishes "never checked" via LastCheckedAt.
	PendingUpdates int
	// PendingPackages is the de-duplicated union of every
	// `system_updaters.pending_packages` row for this system —
	// what the operator would update if they hit Apply. Surfaced
	// for the systems-list hover tooltip; empty when no check has
	// ever produced markers. De-dupe key is (Name, OldVersion,
	// NewVersion) so two managers reporting the same package at
	// different versions both surface.
	PendingPackages []PendingPackage
	// LastRunFailed is true when the most recent terminated run
	// against this system (any kind) exited non-zero. The systems
	// handler exposes this so the SPA can flip the row glyph to
	// red even on a reachable host.
	LastRunFailed bool
	// LastRunReason summarises the failure for the "Needs
	// Attention" line on the detail page — short and stable, like
	// "apply exit 2".
	LastRunReason string
	// Running is true when an updater run currently holds the
	// per-system advisory lock. Lets the SPA paint a spinner on
	// rows whose work was kicked off from another tab/page, and
	// keep it lit across navigation.
	Running bool
}

// MaxLogTailBytes is the cap on Run.LogTail at write time. ~12 KB
// holds a healthy slice of an ansible failure trace without
// inflating the DB; chatty playbooks get truncated, never
// stream-stored.
const MaxLogTailBytes = 12 * 1024

// Sentinel errors used across the package.
var (
	ErrNotFound     = errors.New("updaters: not found")
	ErrInvalid      = errors.New("updaters: invalid input")
	ErrConflict     = errors.New("updaters: another run is in progress for this system")
	ErrBuiltinWrite = errors.New("updaters: builtins cannot be modified at runtime")
	ErrReservedID   = errors.New("updaters: id namespace reserved")
	ErrDuplicate    = errors.New("updaters: definition with this id already exists")
	ErrCheckOnly    = errors.New("updaters: updater is check-only and cannot be applied")
)

// IsBuiltinID reports whether id falls in the reserved builtin
// namespace.
func IsBuiltinID(id string) bool {
	return strings.HasPrefix(id, PrefixBuiltin)
}

// IsCustomID reports whether id falls in the reserved custom
// namespace.
func IsCustomID(id string) bool {
	return strings.HasPrefix(id, PrefixCustom)
}
