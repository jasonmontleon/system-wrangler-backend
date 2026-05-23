// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/audit"
)

// AnsibleRunner is the slice of *ansible.Runner this package depends
// on. Interface-shaped so tests can inject a fake.
type AnsibleRunner interface {
	Run(ctx context.Context, req ansible.Request) (ansible.Run, error)
}

// Locker is the per-system advisory lock contract. Reused from the
// updater substrate's `updater_run_locks` row so concurrent updater
// + exporter activity on the same host serialises through a single
// row. *updaters.SQLiteStore satisfies it via its existing methods;
// any future rename of the table (tracked in project_roadmap.md)
// rebinds the interface without touching this package.
type Locker interface {
	AcquireLock(systemID, runID string, at time.Time) error
	ReleaseLock(systemID, runID string) error
	ConflictingRun(systemID string) (string, error)
}

// Runner coordinates install / status / remove against the ansible
// substrate. All three operations serialise per-system via Locker
// so two operators can't drive concurrent ansible sessions against
// the same host.
type Runner struct {
	Registry *Registry
	Store    Store
	Locker   Locker
	Ansible  AnsibleRunner
	Audit    *audit.Store

	Now   func() time.Time
	NewID func() string
	// RunHistoryLimit returns the per-system cap on exporter_runs
	// rows. nil disables the trim.
	RunHistoryLimit func() int
	// Notify, if set, is called at lifecycle boundaries for every
	// run that successfully acquires the per-system lock:
	// "exporter.run.started" + "systems.changed" on entry,
	// "exporter.run.completed" + "systems.changed" on exit.
	Notify func(eventType string)
}

func (r *Runner) notify(eventType string) {
	if r.Notify == nil {
		return
	}
	r.Notify(eventType)
}

// RunResult is the outcome of one install / status / remove call.
type RunResult struct {
	Run        Run
	ExporterID string
	Kind       RunKind
	Status     ansible.RunStatus
	ExitCode   int
	State      State
	Port       int
	Service    string
	Reason     string
}

// Install runs the named installer's install.yml against the
// system, parses the SW_EXPORTER_* markers, and upserts
// system_exporters with the observed state.
func (r *Runner) Install(ctx context.Context, systemID, exporterID string) (RunResult, error) {
	return r.runOne(ctx, systemID, exporterID, RunKindInstall)
}

// Status runs the named installer's status.yml against the system —
// the lighter-weight "Inspect now" equivalent. Same marker parsing
// and audit shape as Install; the SystemExporter row is upserted
// with state but last_install_at is not touched.
func (r *Runner) Status(ctx context.Context, systemID, exporterID string) (RunResult, error) {
	return r.runOne(ctx, systemID, exporterID, RunKindStatus)
}

// Remove runs the named installer's remove.yml against the system
// and marks the SystemExporter row as removed on success.
func (r *Runner) Remove(ctx context.Context, systemID, exporterID string) (RunResult, error) {
	return r.runOne(ctx, systemID, exporterID, RunKindRemove)
}

func (r *Runner) runOne(ctx context.Context, systemID, exporterID string, kind RunKind) (RunResult, error) {
	if err := r.validate(); err != nil {
		return RunResult{}, err
	}
	if systemID == "" || exporterID == "" {
		return RunResult{}, fmt.Errorf("%w: system_id and exporter_id required", ErrInvalid)
	}
	def, err := r.Registry.Get(exporterID)
	if err != nil {
		return RunResult{}, err
	}
	if def.IsDeleted() {
		return RunResult{}, fmt.Errorf("%w: exporter %q is deleted", ErrNotFound, exporterID)
	}

	var body []byte
	switch kind {
	case RunKindInstall:
		body = def.InstallPlaybook
	case RunKindStatus:
		body = def.StatusPlaybook
	case RunKindRemove:
		if !def.HasRemove() {
			return RunResult{}, fmt.Errorf("%w: %s", ErrNoRemove, exporterID)
		}
		body = def.RemovePlaybook
	default:
		return RunResult{}, fmt.Errorf("%w: invalid run kind %q", ErrInvalid, string(kind))
	}

	now := r.now()
	runID := r.newID()
	sha := shaHex(body)
	run := Run{
		ID:          runID,
		SystemID:    systemID,
		ExporterID:  exporterID,
		Kind:        kind,
		StartedAt:   now,
		ActorID:     actorID(ctx),
		PlaybookSHA: sha,
	}
	if err := r.Store.InsertRun(run); err != nil {
		return RunResult{}, err
	}
	r.trimHistory(systemID)
	if err := r.Locker.AcquireLock(systemID, runID, now); err != nil {
		if errors.Is(err, conflictFromLocker(err)) {
			r.finishRun(run, now, -1, "conflict: another run is in progress")
			return RunResult{Run: run, ExporterID: exporterID, Kind: kind, Status: ansible.RunFailure, Reason: "conflict"}, ErrConflict
		}
		r.finishRun(run, now, -1, "acquire lock failed: "+err.Error())
		return RunResult{Run: run, ExporterID: exporterID, Kind: kind, Status: ansible.RunFailure}, err
	}
	r.notify("exporter.run.started")
	r.notify("systems.changed")
	defer func() {
		_ = r.Locker.ReleaseLock(systemID, runID)
		r.notify("exporter.run.completed")
		r.notify("systems.changed")
	}()

	startAction, completeAction := auditActions(kind)
	r.logStart(ctx, audit.Event{
		ID:         runID,
		Action:     startAction,
		Outcome:    audit.Success,
		TargetKind: "system",
		TargetID:   systemID,
		Detail: audit.Detail{
			"run_id":       runID,
			"exporter_id":  exporterID,
			"playbook_sha": sha,
		},
	})

	playbookPath, cleanup, err := writePlaybook(body, string(kind))
	if err != nil {
		r.finishRun(run, r.now(), -1, "write playbook: "+err.Error())
		r.logComplete(ctx, completeAction, audit.Failure, systemID, runID, run.StartedAt, audit.Detail{
			"exporter_id": exporterID,
			"status":      string(ansible.RunFailure),
			"reason":      "write playbook: " + err.Error(),
		})
		return RunResult{Run: run, ExporterID: exporterID, Kind: kind, Status: ansible.RunFailure, Reason: err.Error()}, nil
	}
	defer cleanup()

	aRun, aErr := r.Ansible.Run(ctx, ansible.Request{
		SystemID:     systemID,
		PlaybookPath: playbookPath,
		OmitAudit:    true,
	})
	finishedAt := r.now()
	status := aRun.Status
	exit := aRun.ExitCode
	logTail := combineOutput(aRun.Stdout, aRun.Stderr)
	r.finishRun(run, finishedAt, exit, logTail)

	markers := ParseMarkers(aRun.Stdout)
	port := markers.Port
	if port == 0 {
		port = def.BindPort
	}
	observed := markers.State()
	if kind == RunKindRemove {
		// Remove explicitly transitions the row to "removed" on
		// success regardless of what the playbook emitted (there
		// might not be anything to probe after a clean uninstall).
		if aErr == nil && status == ansible.RunSuccess {
			observed = StateRemoved
		}
	}
	if aErr != nil || status != ansible.RunSuccess {
		// Hard failure paths force a "failed" reading so the row
		// reflects the truth ("we tried, the host disagreed") even
		// when the playbook never reached its debug tasks.
		observed = StateFailed
	}

	reason := ""
	if aErr != nil {
		reason = aErr.Error()
	} else if status != ansible.RunSuccess {
		reason = fmt.Sprintf("ansible status %s, exit %d", status, exit)
	}

	if kind == RunKindRemove && aErr == nil && status == ansible.RunSuccess {
		if err := r.Store.MarkRemoved(systemID, exporterID, finishedAt, reason); err != nil && !errors.Is(err, ErrNotFound) {
			slog.Warn("exporters: mark removed", "err", err, "system_id", systemID, "exporter_id", exporterID) //nolint:gosec
		}
	} else {
		row := SystemExporter{
			SystemID:     systemID,
			ExporterID:   exporterID,
			State:        observed,
			Port:         port,
			ServiceName:  markers.ServiceName,
			LastStatusAt: &finishedAt,
			LastReason:   reason,
		}
		if kind == RunKindInstall && aErr == nil {
			row.LastInstallAt = &finishedAt
		}
		if err := r.Store.UpsertSystemExporter(row); err != nil {
			slog.Warn("exporters: upsert system_exporter", "err", err, "system_id", systemID, "exporter_id", exporterID) //nolint:gosec
		}
	}

	outcome := audit.Success
	if aErr != nil || status != ansible.RunSuccess {
		outcome = audit.Failure
	}
	detail := audit.Detail{
		"parent_id":   runID,
		"exporter_id": exporterID,
		"status":      string(status),
		"exit_code":   exit,
		"duration_ms": finishedAt.Sub(run.StartedAt).Milliseconds(),
		"state":       string(observed),
		"port":        port,
		"log_sha":     shaHex([]byte(logTail)),
	}
	if reason != "" {
		detail["reason"] = reason
	}
	r.logComplete(ctx, completeAction, outcome, systemID, runID, run.StartedAt, detail)

	if aErr != nil {
		return RunResult{
			Run:        run,
			ExporterID: exporterID,
			Kind:       kind,
			Status:     ansible.RunFailure,
			ExitCode:   exit,
			State:      observed,
			Port:       port,
			Service:    markers.ServiceName,
			Reason:     reason,
		}, aErr
	}
	return RunResult{
		Run:        run,
		ExporterID: exporterID,
		Kind:       kind,
		Status:     status,
		ExitCode:   exit,
		State:      observed,
		Port:       port,
		Service:    markers.ServiceName,
		Reason:     reason,
	}, nil
}

// conflictFromLocker normalises the locker's conflict signal back to
// our package-local ErrConflict. The updaters package's
// ErrConflict is a different sentinel, so the wrapped errors.Is
// chain doesn't match — we look for the substring as the stable
// contract. The locker's contract is "returns a sentinel containing
// 'another run is in progress'", which both updaters.ErrConflict and
// any future Locker satisfy.
func conflictFromLocker(err error) error {
	if err == nil {
		return nil
	}
	// The updaters package returns its own sentinel; we treat any
	// "another run is in progress" wrapping as a conflict so callers
	// of either substrate get a uniform 409.
	if isConflict(err) {
		return err
	}
	return nil
}

// isConflict matches both the local ErrConflict and the updater
// package's analog by looking for the canonical "another run is in
// progress" phrase. Keeps the runner free of an exporters→updaters
// edge.
func isConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrConflict) {
		return true
	}
	return contains(err.Error(), "another run is in progress")
}

func contains(s, sub string) bool {
	return len(sub) == 0 || len(s) >= len(sub) && indexOf(s, sub) >= 0
}

// indexOf is a tiny strings.Index without the import — keeps this
// helper self-contained for readability.
func indexOf(s, sub string) int {
	n := len(sub)
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == sub {
			return i
		}
	}
	return -1
}

func (r *Runner) trimHistory(systemID string) {
	if r.RunHistoryLimit == nil {
		return
	}
	keep := r.RunHistoryLimit()
	if keep <= 0 {
		return
	}
	if err := r.Store.TrimRunsForSystem(systemID, keep); err != nil {
		slog.Warn("exporters: trim run history", "err", err, "system_id", systemID) //nolint:gosec
	}
}

func (r *Runner) finishRun(run Run, finishedAt time.Time, exit int, logTail string) {
	if err := r.Store.FinishRun(run.ID, finishedAt, exit, logTail); err != nil {
		slog.Warn("exporters: finish run", "err", err, "run_id", run.ID)
	}
}

func (r *Runner) logStart(ctx context.Context, e audit.Event) {
	if r.Audit == nil {
		return
	}
	if err := r.Audit.Log(ctx, e); err != nil {
		slog.Error("exporters: audit log", "err", err, "action", e.Action)
	}
}

func (r *Runner) logComplete(
	ctx context.Context,
	action string,
	outcome audit.Outcome,
	systemID, parentID string,
	startedAt time.Time,
	detail audit.Detail,
) {
	if r.Audit == nil {
		return
	}
	if _, ok := detail["parent_id"]; !ok {
		detail["parent_id"] = parentID
	}
	if _, ok := detail["duration_ms"]; !ok {
		detail["duration_ms"] = r.now().Sub(startedAt).Milliseconds()
	}
	if err := r.Audit.Log(ctx, audit.Event{
		Action:     action,
		Outcome:    outcome,
		TargetKind: "system",
		TargetID:   systemID,
		Detail:     detail,
	}); err != nil {
		slog.Error("exporters: audit log", "err", err, "action", action)
	}
}

func (r *Runner) validate() error {
	if r.Registry == nil || r.Store == nil || r.Locker == nil || r.Ansible == nil {
		return fmt.Errorf("%w: runner is not fully wired", ErrInvalid)
	}
	return nil
}

func (r *Runner) now() time.Time {
	if r.Now == nil {
		return time.Now().UTC()
	}
	return r.Now().UTC()
}

func (r *Runner) newID() string {
	if r.NewID == nil {
		return newUUID()
	}
	return r.NewID()
}

func writePlaybook(body []byte, kind string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "sw-exporter-"+kind+"-")
	if err != nil {
		return "", func() {}, fmt.Errorf("exporters: mkdir tmp: %w", err)
	}
	cleanup := func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("exporters: temp dir cleanup", "err", rmErr, "dir", dir)
		}
	}
	path := filepath.Join(dir, "playbook.yml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("exporters: write playbook: %w", err)
	}
	return path, cleanup, nil
}

func combineOutput(stdout, stderr []byte) string {
	if len(stderr) == 0 {
		return string(stdout)
	}
	if len(stdout) == 0 {
		return string(stderr)
	}
	return string(stdout) + "\n--- stderr ---\n" + string(stderr)
}

func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func actorID(ctx context.Context) string {
	a := audit.ActorFromContext(ctx)
	return a.ID
}

func auditActions(k RunKind) (string, string) {
	switch k {
	case RunKindStatus:
		return "system.exporter.status.start", "system.exporter.status.complete"
	case RunKindRemove:
		return "system.exporter.remove.start", "system.exporter.remove.complete"
	default:
		return "system.exporter.install.start", "system.exporter.install.complete"
	}
}
