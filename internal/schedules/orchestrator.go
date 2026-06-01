// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"system-wrangler-backend/internal/audit"
)

// Orchestrator dispatches one schedule's worth of work: resolve
// targets, fan out check/apply per host, optionally reboot any host
// whose reboot_required flag is set, then aggregate the outcome and
// write the final schedule_runs row. Per-schedule advisory locking
// prevents an overlapping fire from racing the previous one — a
// slow schedule simply skips its next tick rather than stacking up.
type Orchestrator struct {
	Store    Store
	Systems  SystemStore
	Labels   LabelStore
	Registry UpdaterRegistry
	Updaters UpdaterAvailabilityStore
	Runner   UpdaterRunner
	Ansible  AnsibleRunner
	Clearer  RebootClearer
	Audit    *audit.Store
	// Now overrides the orchestrator's clock for tests. Defaults to nil
	// → audit rows fall through to the audit store's own clock.
	Now func() time.Time //nolint:unused // reserved for future fire-window hysteresis

	locks sync.Map // map[scheduleID]*sync.Mutex
}

// Fire runs `sch` end-to-end. It is safe to call concurrently with
// fires for other schedules; concurrent fires for the *same*
// schedule will skip the second caller (returning nil + a "skipped"
// log line). Errors come back only for setup failures the caller
// might want to surface (e.g. store I/O on RecordRunStart); per-
// target failures are tallied in the returned ScheduleRun rather
// than bubbled.
func (o *Orchestrator) Fire(ctx context.Context, sch Schedule) (ScheduleRun, error) {
	lockAny, _ := o.locks.LoadOrStore(sch.ID, &sync.Mutex{})
	lock := lockAny.(*sync.Mutex)
	if !lock.TryLock() {
		slog.Info("schedules: skipping overlapping fire", "schedule_id", sch.ID, "name", sch.Name)
		return ScheduleRun{}, nil
	}
	defer lock.Unlock()

	run, err := o.Store.RecordRunStart(sch.ID)
	if err != nil {
		return ScheduleRun{}, fmt.Errorf("schedules: record run start: %w", err)
	}

	targets, err := ResolveTargets(sch, o.Systems, o.Labels)
	if err != nil {
		// Setup failures finish the run as failed so the operator
		// can see what happened on the next list.
		msg := "resolve targets: " + err.Error()
		_ = o.Store.RecordRunFinish(run.ID, StatusFailed, 0, 0, 0, msg)
		o.logAudit(ctx, sch, run.ID, audit.Failure, msg)
		run.Status = StatusFailed
		run.Message = msg
		return run, nil
	}

	// Per-host fan-out runs in parallel goroutines. The updater
	// Runner already owns the cross-host concurrency cap via its
	// Gate (settings.UpdateConcurrencyLimit) so we don't reimplement
	// rate-limiting here — we just dispatch all hosts at once and
	// let the Gate block whoever exceeds the limit. The per-system
	// advisory lock inside updaters.Runner remains the guarantee that
	// two runs on the *same* host never overlap.
	var (
		attempted = len(targets)
		succeeded int
		failed    int
		mu        sync.Mutex
		wg        sync.WaitGroup
	)
	for _, sys := range targets {
		wg.Add(1)
		go func(sysID string) {
			defer wg.Done()
			hostOK := true
			if sch.RunCheck {
				r := FanOutOnSystem(ctx, sysID, FanOutCheck, o.Registry, o.Updaters, o.Runner)
				if r.Failed > 0 || (r.Skipped && r.Reason != "no enabled updaters for this action") {
					hostOK = false
				}
			}
			if sch.RunApply && hostOK {
				r := FanOutOnSystem(ctx, sysID, FanOutApply, o.Registry, o.Updaters, o.Runner)
				if r.Failed > 0 || (r.Skipped && r.Reason != "no enabled updaters for this action") {
					hostOK = false
				}
			}
			if sch.RebootAfterApply && sch.RunApply && hostOK && o.Ansible != nil && o.Clearer != nil {
				if _, rebootErr := RebootIfRequired(ctx, sysID, o.Systems, o.Clearer, o.Ansible); rebootErr != nil {
					hostOK = false
				}
			}
			mu.Lock()
			if hostOK {
				succeeded++
			} else {
				failed++
			}
			mu.Unlock()
		}(sys.ID)
	}
	wg.Wait()

	status := finalStatus(attempted, succeeded, failed)
	message := fmt.Sprintf("%d/%d hosts ok", succeeded, attempted)
	if err := o.Store.RecordRunFinish(run.ID, status, attempted, succeeded, failed, message); err != nil {
		slog.Error("schedules: record run finish", "err", err, "schedule_id", sch.ID)
	}
	outcome := audit.Success
	if status != StatusSuccess {
		outcome = audit.Failure
	}
	o.logAudit(ctx, sch, run.ID, outcome, message)
	run.Status = status
	run.TargetsAttempted = attempted
	run.TargetsSucceeded = succeeded
	run.TargetsFailed = failed
	run.Message = message
	return run, nil
}

func finalStatus(attempted, succeeded, failed int) RunStatus {
	switch {
	case attempted == 0:
		// No targets matched. Not really a failure — but we mark it
		// so the operator notices and either widens the target or
		// disables the schedule.
		return StatusSuccess
	case failed == 0:
		return StatusSuccess
	case succeeded == 0:
		return StatusFailed
	default:
		return StatusPartial
	}
}

func (o *Orchestrator) logAudit(ctx context.Context, sch Schedule, runID string, outcome audit.Outcome, msg string) {
	if o.Audit == nil {
		return
	}
	if err := o.Audit.Log(ctx, audit.Event{
		Action:      "schedule.run",
		Outcome:     outcome,
		TargetKind:  "schedule",
		TargetID:    sch.ID,
		TargetLabel: sch.Name,
		Detail:      audit.Detail{"run_id": runID, "summary": msg},
	}); err != nil {
		slog.Error("schedules: audit log", "err", err, "schedule_id", sch.ID)
	}
}
