// SPDX-License-Identifier: Apache-2.0

// Package exporters owns the substrate for "install a Prometheus
// exporter on this remote system." It mirrors the updaters package
// deliberately — same Definition / Registry / Store / Runner split,
// same builtin-plus-custom union, same per-system lock and SSE
// pipeline. Cross-substrate parallelism keeps the operator mental
// model and the maintenance surface small.
//
// Each builtin lives under internal/exporters/builtins/<id>/ as a
// pair of YAML playbooks (install.yml + status.yml, optional
// remove.yml) embedded via go:embed. Custom installers are
// Global-Admin-managed rows in exporter_definitions.
//
// Per-system serialisation reuses the existing updater_run_locks
// row via the Locker interface so concurrent updater + exporter
// activity on the same host cannot collide. Design and discipline:
// research/exporter-deployment.md.
package exporters

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

// Source values. SourceBuiltin definitions ship in the Go binary;
// SourceCustom rows are Global-Admin-managed entries in
// exporter_definitions.
const (
	SourceBuiltin Source = "builtin"
	SourceCustom  Source = "custom"
)

// PrefixBuiltin and PrefixCustom reserve the two id namespaces. The
// registry refuses any operation that violates the matching
// invariant. Mirrors the updaters package so operators can read one
// rulebook for both substrates.
const (
	PrefixBuiltin = "builtin."
	PrefixCustom  = "custom."
)

// MaxPlaybookBytes caps each playbook body. 64 KB matches the
// updaters cap; the dnf builtin sits in the 2–3 KB range.
const MaxPlaybookBytes = 64 * 1024

// ExporterKind discriminates the wire-protocol family an installer
// targets. The exporter substrate ships with two kinds; future
// additions (process_exporter, blackbox_exporter, …) widen the enum.
type ExporterKind string

// Known exporter kinds.
const (
	KindNodeExporter    ExporterKind = "node_exporter"
	KindWindowsExporter ExporterKind = "windows_exporter"
)

// IsValid reports whether k names a known exporter kind.
func (k ExporterKind) IsValid() bool {
	return k == KindNodeExporter || k == KindWindowsExporter
}

// ScrapeMode is the per-system transport / auth selection. v1 only
// wires localhost; mtls-self and mtls-byo land in phases 5–6 and
// are enumerated here so the schema check constraint matches the
// design without a later migration.
type ScrapeMode string

// Scrape modes stored on system_exporter_settings.scrape_mode.
const (
	ScrapeLocalhost ScrapeMode = "localhost"
	ScrapeMTLSSelf  ScrapeMode = "mtls-self"
	ScrapeMTLSByo   ScrapeMode = "mtls-byo"
)

// IsValid reports whether m is one of the three known scrape modes.
func (m ScrapeMode) IsValid() bool {
	return m == ScrapeLocalhost || m == ScrapeMTLSSelf || m == ScrapeMTLSByo
}

// State is the system_exporters.state column — what we last
// observed about this exporter on this system. Removed is a logical
// tombstone for a system the operator uninstalled via remove.yml;
// it lets the Monitoring tab differentiate "never installed" from
// "explicitly removed" without scanning audit history.
type State string

// system_exporters.state values.
const (
	StateInstalled State = "installed"
	StateRunning   State = "running"
	StateFailed    State = "failed"
	StateRemoved   State = "removed"
)

// IsValid reports whether s names a known state.
func (s State) IsValid() bool {
	return s == StateInstalled || s == StateRunning || s == StateFailed || s == StateRemoved
}

// pkgManagerPattern restricts AppliesToPkgManager to the same charset
// as an updater id; it must match a real updater id like "builtin.dnf"
// or "custom.foo" so the runtime cross-check has a target.
var pkgManagerPattern = regexp.MustCompile(`^(?:builtin|custom)\.[A-Za-z0-9._-]{1,64}$`)

// Definition is a single registered exporter installer. The two
// required playbook bodies are install.yml and status.yml; remove.yml
// is optional and gates the Remove action in the UI. BindPort is the
// default listen port the installer hands to the exporter binary —
// the playbook is free to override and surface a different port via
// the SW_EXPORTER_PORT marker.
type Definition struct {
	ID                  string
	Source              Source
	DisplayName         string
	Description         string
	AppliesToPkgManager string // updater id this installer targets, e.g. "builtin.dnf"
	ExporterKind        ExporterKind
	BindPort            int
	InstallPlaybook     []byte
	StatusPlaybook      []byte
	RemovePlaybook      []byte
	CreatedBy           string    // empty for builtins
	CreatedAt           time.Time // zero for builtins
	UpdatedAt           time.Time // zero for builtins
	DeletedAt           *time.Time
}

// IsDeleted reports whether d carries a soft-delete tombstone.
// Builtins never carry one; deleted custom definitions are still
// returned by audit and run-history lookups so the name resolves.
func (d Definition) IsDeleted() bool {
	return d.DeletedAt != nil && !d.DeletedAt.IsZero()
}

// HasRemove reports whether this definition declares an optional
// remove.yml. The system-scoped handler refuses /remove when this is
// false.
func (d Definition) HasRemove() bool {
	return len(d.RemovePlaybook) > 0
}

// Validate enforces input-side invariants for custom definitions.
// Builtins skip Validate at runtime — they're frozen at compile time
// and exercised by the package-init duplicate-id panic in registry.go.
func (d Definition) Validate() error {
	d.DisplayName = strings.TrimSpace(d.DisplayName)
	d.AppliesToPkgManager = strings.TrimSpace(d.AppliesToPkgManager)
	if d.DisplayName == "" {
		return errors.New("exporters: display_name required")
	}
	if d.AppliesToPkgManager == "" {
		return errors.New("exporters: applies_to_pkg_manager required")
	}
	if !pkgManagerPattern.MatchString(d.AppliesToPkgManager) {
		return errors.New("exporters: applies_to_pkg_manager must look like an updater id (builtin.<name> or custom.<slug>)")
	}
	if !d.ExporterKind.IsValid() {
		return errors.New("exporters: exporter_kind must be node_exporter or windows_exporter")
	}
	if d.BindPort < 1 || d.BindPort > 65535 {
		return errors.New("exporters: bind_port must be between 1 and 65535")
	}
	if len(d.InstallPlaybook) == 0 {
		return errors.New("exporters: install_playbook required")
	}
	if len(d.StatusPlaybook) == 0 {
		return errors.New("exporters: status_playbook required")
	}
	if len(d.InstallPlaybook) > MaxPlaybookBytes {
		return errors.New("exporters: install_playbook exceeds 64 KB cap")
	}
	if len(d.StatusPlaybook) > MaxPlaybookBytes {
		return errors.New("exporters: status_playbook exceeds 64 KB cap")
	}
	if len(d.RemovePlaybook) > MaxPlaybookBytes {
		return errors.New("exporters: remove_playbook exceeds 64 KB cap")
	}
	return nil
}

// SystemExporter is one row in system_exporters — last observed
// state for (system, exporter). Absence of a row means "never
// installed." A row with State=StateRemoved means the operator ran
// remove.yml; the Monitoring tab shows that distinctly so a re-
// install is one click.
type SystemExporter struct {
	SystemID      string
	ExporterID    string
	State         State
	Port          int
	ServiceName   string
	LastStatusAt  *time.Time
	LastInstallAt *time.Time
	LastReason    string
}

// SystemSettings is the per-system row in system_exporter_settings.
// v1 only consumes ScrapeMode; the row is missing entirely until
// the operator first interacts with the Monitoring tab, at which
// point the runner upserts a default (ScrapeLocalhost) row.
type SystemSettings struct {
	SystemID   string
	ScrapeMode ScrapeMode
}

// RunKind classifies an exporter_runs row. Install / status / remove
// match the three system-scoped endpoints.
type RunKind string

// RunKind values stored in exporter_runs.kind.
const (
	RunKindInstall RunKind = "install"
	RunKindStatus  RunKind = "status"
	RunKindRemove  RunKind = "remove"
)

// IsValid reports whether k is one of the known kinds.
func (k RunKind) IsValid() bool {
	return k == RunKindInstall || k == RunKindStatus || k == RunKindRemove
}

// Run is one row in exporter_runs. LogTail is the trailing ~12 KB
// of ansible stdout/stderr captured at finish; the full stream is
// not persisted.
type Run struct {
	ID          string
	SystemID    string
	ExporterID  string
	Kind        RunKind
	StartedAt   time.Time
	FinishedAt  *time.Time
	ExitCode    *int
	ActorID     string
	PlaybookSHA string
	LogTail     string
}

// MaxLogTailBytes is the per-run log cap on write. Matches updaters
// so the SPA's "Show" toggle has the same body size on both
// substrates.
const MaxLogTailBytes = 12 * 1024

// Sentinel errors used across the package. Mirror the updater shape
// where reasonable so handlers can share error→status maps.
var (
	ErrNotFound     = errors.New("exporters: not found")
	ErrInvalid      = errors.New("exporters: invalid input")
	ErrConflict     = errors.New("exporters: another run is in progress for this system")
	ErrBuiltinWrite = errors.New("exporters: builtins cannot be modified at runtime")
	ErrReservedID   = errors.New("exporters: id namespace reserved")
	ErrDuplicate    = errors.New("exporters: definition with this id already exists")
	ErrNoRemove     = errors.New("exporters: this installer does not declare a remove playbook")
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
