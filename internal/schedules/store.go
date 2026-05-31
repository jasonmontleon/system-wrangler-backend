// SPDX-License-Identifier: Apache-2.0

package schedules

import "time"

// Store is the persistence contract for schedules + their run history.
// Implementations are responsible for computing NextRunAt from the
// schedule's cron expression on Create/Update — the handler does not
// recompute it so callers don't have to know about the clock or the
// parser.
type Store interface {
	Create(in ScheduleInput, createdBy string) (Schedule, error)
	Get(id string) (Schedule, error)
	List() ([]Schedule, error)
	Update(id string, in ScheduleInput) (Schedule, error)
	Delete(id string) error

	// SetEnabled toggles the enabled flag and recomputes NextRunAt
	// (clearing it when disabling) without rewriting any other field.
	SetEnabled(id string, enabled bool) (Schedule, error)

	// RecordRunStart inserts a new schedule_runs row in `running`
	// status. The store generates the id and start timestamp; the
	// returned run carries both. Used by the Phase 2 ticker.
	RecordRunStart(scheduleID string) (ScheduleRun, error)

	// RecordRunFinish patches an existing run row with the final
	// status, finished timestamp, attempted/succeeded/failed counts,
	// and an optional message. Also updates the parent schedule's
	// last_run_at / last_status and advances NextRunAt.
	RecordRunFinish(runID string, status RunStatus, attempted, succeeded, failed int, message string) error

	// ListRuns returns the schedule's run history, most recent first,
	// capped at `limit` rows. limit <= 0 means "no cap" (callers
	// should pass a sensible value — the handler defaults to 50).
	ListRuns(scheduleID string, limit int) ([]ScheduleRun, error)

	// Due returns enabled schedules whose NextRunAt is at or before
	// `now`. Phase 2's ticker calls this once per minute.
	Due(now time.Time) ([]Schedule, error)
}
