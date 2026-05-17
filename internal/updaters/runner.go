// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"system-wrangler-backend/internal/ansible"
	"system-wrangler-backend/internal/audit"
)

// AnsibleRunner is the slice of *ansible.Runner this package depends
// on. Defining it as an interface lets tests inject a fake without
// pulling the whole credentials + host-key chain into a unit-test
// fixture.
type AnsibleRunner interface {
	Run(ctx context.Context, req ansible.Request) (ansible.Run, error)
}

// Runner coordinates inspect / check / apply against the ansible
// substrate. Builtins flow straight from the embedded registry;
// custom updaters are pulled from Store via Registry. All three
// operations serialise per-system via Store's advisory lock so two
// operators can't drive concurrent ansible sessions against the
// same host.
type Runner struct {
	Registry *Registry
	Store    Store
	Ansible  AnsibleRunner
	Audit    *audit.Store

	Now   func() time.Time
	NewID func() string
	// RunHistoryLimit returns the per-system cap on updater_runs
	// rows. Bound in main.go to the settings package's typed
	// accessor; left nil in tests where retention is irrelevant
	// (the trim is then a no-op).
	RunHistoryLimit func() int
	// Gate caps how many check/apply tasks run simultaneously
	// across the fleet. A nil Gate disables the cap entirely; tests
	// that don't exercise queuing leave it unset.
	Gate *Gate
}

// InspectResult is the outcome of one inspect call. Detected lists
// the updater IDs the playbook found on the target; Removed lists
// IDs whose rows existed before this run but no longer have the
// binary present.
type InspectResult struct {
	Run      Run
	Status   ansible.RunStatus
	Detected []string
	Removed  []string
	ExitCode int
	Reason   string
}

// RunResult is the outcome of one check or apply call. AffectedCount
// is the integer the playbook surfaced via the SW_AFFECTED_COUNT
// marker; 0 when the playbook didn't emit one.
type RunResult struct {
	Run           Run
	UpdaterID     string
	Kind          RunKind
	Status        ansible.RunStatus
	ExitCode      int
	AffectedCount int
	Reason        string
}

// Inspect composes an inspection playbook from the registry, runs
// it against the system, reconciles system_updaters, and emits the
// system.inspect.start / system.inspect.complete pair. The audit
// rows share an id so the complete-row's detail.parent_id resolves.
func (r *Runner) Inspect(ctx context.Context, systemID string) (InspectResult, error) {
	if err := r.validate(); err != nil {
		return InspectResult{}, err
	}
	now := r.now()
	newID := r.newID()

	defs, err := r.Registry.All()
	if err != nil {
		return InspectResult{}, fmt.Errorf("updaters: registry: %w", err)
	}
	if len(defs) == 0 {
		return InspectResult{}, fmt.Errorf("%w: registry has no updaters", ErrInvalid)
	}

	runID := newID
	body := inspectionPlaybook(defs)
	sha := shaHex(body)

	run := Run{
		ID:          runID,
		SystemID:    systemID,
		UpdaterID:   "",
		Kind:        RunKindInspect,
		StartedAt:   now,
		ActorID:     actorID(ctx),
		PlaybookSHA: sha,
	}
	if err := r.Store.InsertRun(run); err != nil {
		return InspectResult{}, err
	}
	r.trimHistory(systemID)
	if err := r.Store.AcquireLock(systemID, runID, now); err != nil {
		if errors.Is(err, ErrConflict) {
			r.finishRun(run, now, -1, 0, "conflict: another run is in progress")
			return InspectResult{Run: run, Status: ansible.RunFailure, Reason: "conflict"}, err
		}
		r.finishRun(run, now, -1, 0, "acquire lock failed: "+err.Error())
		return InspectResult{Run: run, Status: ansible.RunFailure}, err
	}
	defer func() { _ = r.Store.ReleaseLock(systemID, runID) }()

	r.logStart(ctx, audit.Event{
		ID:         runID,
		Action:     "system.inspect.start",
		Outcome:    audit.Success,
		TargetKind: "system",
		TargetID:   systemID,
		Detail:     audit.Detail{"run_id": runID, "updater_count": len(defs)},
	})

	playbookPath, cleanup, err := writePlaybook(body, "inspect")
	if err != nil {
		r.finishRun(run, r.now(), -1, 0, "write playbook: "+err.Error())
		r.logComplete(ctx, "system.inspect.complete", audit.Failure, systemID, runID, run.StartedAt, audit.Detail{
			"status": string(ansible.RunFailure),
			"reason": "write playbook: " + err.Error(),
		})
		return InspectResult{Run: run, Status: ansible.RunFailure, Reason: err.Error()}, nil
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
	// Inspect runs don't surface SW_AFFECTED_COUNT (they probe for
	// binaries, not pending packages); record 0 so the column stays
	// numerically clean.
	r.finishRun(run, finishedAt, exit, 0, logTail)

	if aErr != nil {
		r.logComplete(ctx, "system.inspect.complete", audit.Failure, systemID, runID, run.StartedAt, audit.Detail{
			"status":    string(ansible.RunFailure),
			"exit_code": exit,
			"reason":    aErr.Error(),
		})
		return InspectResult{Run: run, Status: ansible.RunFailure, Reason: aErr.Error()}, aErr
	}

	// Reconcile system_updaters: every detected id gets an upsert,
	// every previously-recorded id that is no longer detected gets
	// removed.
	detected := parseDetected(aRun.Stdout)
	detectedIDs := sortedKeys(detected)
	before, err := r.Store.AvailabilityFor(systemID)
	if err != nil {
		slog.Warn("updaters: availability load before reconcile", "err", err)
	}
	removed := []string{}
	for _, id := range detectedIDs {
		if err := r.Store.UpsertAvailability(systemID, id, finishedAt); err != nil {
			slog.Warn("updaters: upsert availability", "err", err, "updater", id)
		}
	}
	for _, a := range before {
		if !detected[a.UpdaterID] {
			if err := r.Store.RemoveAvailability(systemID, a.UpdaterID); err != nil {
				slog.Warn("updaters: remove availability", "err", err, "updater", a.UpdaterID)
			}
			removed = append(removed, a.UpdaterID)
		}
	}

	outcome := audit.Success
	if status != ansible.RunSuccess {
		outcome = audit.Failure
	}
	detail := audit.Detail{
		"parent_id":   runID,
		"status":      string(status),
		"exit_code":   exit,
		"duration_ms": finishedAt.Sub(run.StartedAt).Milliseconds(),
		"detected":    detectedIDs,
	}
	if len(removed) > 0 {
		detail["removed"] = removed
	}
	r.logComplete(ctx, "system.inspect.complete", outcome, systemID, runID, run.StartedAt, detail)

	return InspectResult{
		Run:      run,
		Status:   status,
		Detected: detectedIDs,
		Removed:  removed,
		ExitCode: exit,
	}, nil
}

// Check fires the named updater's check playbook against the
// system. Emits system.update.check.start / complete and stores a
// run row with kind='check'. Returns ErrConflict (wrapped) when the
// per-system lock is held.
func (r *Runner) Check(ctx context.Context, systemID, updaterID string) (RunResult, error) {
	return r.runUpdater(ctx, systemID, updaterID, RunKindCheck)
}

// Apply fires the named updater's apply playbook. Same shape as
// Check; the audit action is system.update.apply.{start,complete}
// and the complete-row detail carries affected_packages plus
// log_sha.
func (r *Runner) Apply(ctx context.Context, systemID, updaterID string) (RunResult, error) {
	return r.runUpdater(ctx, systemID, updaterID, RunKindApply)
}

func (r *Runner) runUpdater(ctx context.Context, systemID, updaterID string, kind RunKind) (RunResult, error) {
	if err := r.validate(); err != nil {
		return RunResult{}, err
	}
	if strings.TrimSpace(systemID) == "" || strings.TrimSpace(updaterID) == "" {
		return RunResult{}, fmt.Errorf("%w: system_id and updater_id required", ErrInvalid)
	}
	def, err := r.Registry.Get(updaterID)
	if err != nil {
		return RunResult{}, err
	}
	if def.IsDeleted() {
		return RunResult{}, fmt.Errorf("%w: updater %q is deleted", ErrNotFound, updaterID)
	}
	body := def.CheckPlaybook
	if kind == RunKindApply {
		body = def.ApplyPlaybook
	}
	if len(body) == 0 {
		return RunResult{}, fmt.Errorf("%w: updater %q has no %s playbook", ErrInvalid, updaterID, kind)
	}

	now := r.now()
	runID := r.newID()
	sha := shaHex(body)
	run := Run{
		ID:          runID,
		SystemID:    systemID,
		UpdaterID:   updaterID,
		Kind:        kind,
		StartedAt:   now,
		ActorID:     actorID(ctx),
		PlaybookSHA: sha,
	}
	if err := r.Store.InsertRun(run); err != nil {
		return RunResult{}, err
	}
	r.trimHistory(systemID)
	if err := r.Store.AcquireLock(systemID, runID, now); err != nil {
		if errors.Is(err, ErrConflict) {
			r.finishRun(run, now, -1, 0, "conflict: another run is in progress")
		}
		return RunResult{Run: run, UpdaterID: updaterID, Kind: kind, Status: ansible.RunFailure, Reason: "conflict"}, err
	}
	defer func() { _ = r.Store.ReleaseLock(systemID, runID) }()

	startAction, completeAction := auditActions(kind)
	r.logStart(ctx, audit.Event{
		ID:         runID,
		Action:     startAction,
		Outcome:    audit.Success,
		TargetKind: "system",
		TargetID:   systemID,
		Detail: audit.Detail{
			"run_id":       runID,
			"updater_id":   updaterID,
			"playbook_sha": sha,
		},
	})

	if r.Gate != nil {
		if err := r.Gate.Acquire(ctx); err != nil {
			r.finishRun(run, r.now(), -1, 0, "cancelled in queue: "+err.Error())
			r.logComplete(ctx, completeAction, audit.Failure, systemID, runID, run.StartedAt, audit.Detail{
				"updater_id": updaterID,
				"status":     string(ansible.RunFailure),
				"reason":     "cancelled in queue: " + err.Error(),
			})
			return RunResult{Run: run, UpdaterID: updaterID, Kind: kind, Status: ansible.RunFailure, Reason: err.Error()}, err
		}
		defer r.Gate.Release()
	}

	playbookPath, cleanup, err := writePlaybook(body, string(kind))
	if err != nil {
		r.finishRun(run, r.now(), -1, 0, "write playbook: "+err.Error())
		r.logComplete(ctx, completeAction, audit.Failure, systemID, runID, run.StartedAt, audit.Detail{
			"updater_id": updaterID,
			"status":     string(ansible.RunFailure),
			"reason":     "write playbook: " + err.Error(),
		})
		return RunResult{Run: run, UpdaterID: updaterID, Kind: kind, Status: ansible.RunFailure, Reason: err.Error()}, nil
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
	affected := parseAffectedCount(aRun.Stdout)
	r.finishRun(run, finishedAt, exit, affected, logTail)
	// Persist the per-package list only on check runs and only when
	// the ansible call itself succeeded structurally. Apply runs
	// don't refresh the list (auto-Check after Apply does that), and
	// a transport-level failure leaves the previous snapshot in
	// place rather than zeroing it out.
	if kind == RunKindCheck && aErr == nil {
		pkgs := parsePendingPackages(aRun.Stdout)
		if err := r.Store.SetPendingPackages(systemID, updaterID, pkgs); err != nil {
			// system_id / updater_id are user-controlled but slog's
			// structured kv form doesn't interpolate them into the
			// message — gosec G706 false positive.
			slog.Warn("updaters: set pending packages", "err", err, "system_id", systemID, "updater_id", updaterID) //nolint:gosec
		}
	}

	if aErr != nil {
		r.logComplete(ctx, completeAction, audit.Failure, systemID, runID, run.StartedAt, audit.Detail{
			"updater_id": updaterID,
			"status":     string(ansible.RunFailure),
			"exit_code":  exit,
			"reason":     aErr.Error(),
		})
		return RunResult{Run: run, UpdaterID: updaterID, Kind: kind, Status: ansible.RunFailure, Reason: aErr.Error()}, aErr
	}

	outcome := audit.Success
	if status != ansible.RunSuccess {
		outcome = audit.Failure
	}
	detail := audit.Detail{
		"parent_id":         runID,
		"updater_id":        updaterID,
		"status":            string(status),
		"exit_code":         exit,
		"duration_ms":       finishedAt.Sub(run.StartedAt).Milliseconds(),
		"affected_packages": affected,
		"log_sha":           shaHex([]byte(logTail)),
	}
	r.logComplete(ctx, completeAction, outcome, systemID, runID, run.StartedAt, detail)

	return RunResult{
		Run:           run,
		UpdaterID:     updaterID,
		Kind:          kind,
		Status:        status,
		ExitCode:      exit,
		AffectedCount: affected,
	}, nil
}

// trimHistory invokes the per-system retention trim using the
// limit callback wired in main. A nil callback or a non-positive
// return value makes the trim a no-op so tests and bootstrap
// states behave safely.
func (r *Runner) trimHistory(systemID string) {
	if r.RunHistoryLimit == nil {
		return
	}
	keep := r.RunHistoryLimit()
	if keep <= 0 {
		return
	}
	if err := r.Store.TrimRunsForSystem(systemID, keep); err != nil {
		slog.Warn("updaters: trim run history", "err", err, "system_id", systemID)
	}
}

func (r *Runner) finishRun(run Run, finishedAt time.Time, exit, affectedCount int, logTail string) {
	if err := r.Store.FinishRun(run.ID, finishedAt, exit, affectedCount, logTail); err != nil {
		slog.Warn("updaters: finish run", "err", err, "run_id", run.ID)
	}
}

func (r *Runner) logStart(ctx context.Context, e audit.Event) {
	if r.Audit == nil {
		return
	}
	if err := r.Audit.Log(ctx, e); err != nil {
		slog.Error("updaters: audit log", "err", err, "action", e.Action)
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
		slog.Error("updaters: audit log", "err", err, "action", action)
	}
}

func (r *Runner) validate() error {
	if r.Registry == nil || r.Store == nil || r.Ansible == nil {
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

// writePlaybook writes body to a per-run temp file and returns
// (path, cleanup, err). The caller defers cleanup. The temp dir is
// a sibling of the ansible runner's per-run temp dir — they don't
// interact, so cleanup is independent.
func writePlaybook(body []byte, kind string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "sw-updater-"+kind+"-")
	if err != nil {
		return "", func() {}, fmt.Errorf("updaters: mkdir tmp: %w", err)
	}
	cleanup := func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("updaters: temp dir cleanup", "err", rmErr, "dir", dir)
		}
	}
	path := filepath.Join(dir, "playbook.yml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("updaters: write playbook: %w", err)
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

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Order matters for deterministic audit detail rendering; the
	// set is small so a O(n log n) sort is fine.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func actorID(ctx context.Context) string {
	a := audit.ActorFromContext(ctx)
	return a.ID
}

func auditActions(k RunKind) (string, string) {
	switch k {
	case RunKindCheck:
		return "system.update.check.start", "system.update.check.complete"
	case RunKindApply:
		return "system.update.apply.start", "system.update.apply.complete"
	default:
		return "system.inspect.start", "system.inspect.complete"
	}
}
