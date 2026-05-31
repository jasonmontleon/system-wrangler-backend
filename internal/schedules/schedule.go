// SPDX-License-Identifier: Apache-2.0

// Package schedules manages cron-driven recurring tasks — primarily
// fleet update fan-outs (Check, Apply, optional reboot-if-required).
// Schedules are persisted with their cron expression, target spec,
// and an enabled flag; the runtime ticker (Phase 2) walks the table
// each minute and fires whichever rows are due.
package schedules

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors returned by the schedules package.
var (
	ErrNotFound = errors.New("schedule not found")
	ErrInvalid  = errors.New("invalid schedule")
)

const maxNameLen = 255

// TargetKind identifies how a schedule chooses its systems at fire
// time. Each kind interprets ScheduleInput.TargetValue differently:
//
//   - TargetGlobal: TargetValue is "" — every system in the inventory.
//   - TargetGroup: TargetValue is a System Group id (string).
//   - TargetSystems: TargetValue is a JSON array of system ids.
//   - TargetSelector: TargetValue is a k8s-subset label selector.
//
// The set is intentionally finite; new target kinds require a schema
// migration so we can't accidentally introduce one with bad scoping.
type TargetKind string

// TargetKind values.
const (
	TargetGlobal   TargetKind = "global"
	TargetGroup    TargetKind = "group"
	TargetSystems  TargetKind = "systems"
	TargetSelector TargetKind = "selector"
)

// RunStatus is the outcome label written on each schedule_runs row.
// "partial" means some targets succeeded and at least one failed —
// this is distinct from "failed" so an operator can tell the
// difference between "the whole fleet was unreachable" and "one host
// failed but the rest worked."
type RunStatus string

// RunStatus values.
const (
	StatusRunning RunStatus = "running"
	StatusSuccess RunStatus = "success"
	StatusPartial RunStatus = "partial"
	StatusFailed  RunStatus = "failed"
)

// Schedule is the persisted representation of one scheduled job.
type Schedule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	CronExpr         string     `json:"cronExpr"`
	Timezone         string     `json:"timezone"`
	RunCheck         bool       `json:"runCheck"`
	RunApply         bool       `json:"runApply"`
	RebootAfterApply bool       `json:"rebootAfterApply"`
	TargetKind       TargetKind `json:"targetKind"`
	TargetValue      string     `json:"targetValue"`
	Enabled          bool       `json:"enabled"`
	NextRunAt        *time.Time `json:"nextRunAt,omitempty"`
	LastRunAt        *time.Time `json:"lastRunAt,omitempty"`
	LastStatus       *RunStatus `json:"lastStatus,omitempty"`
	CreatedBy        string     `json:"createdBy"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

// ScheduleInput is the operator-supplied subset accepted on create
// and update. Server-managed fields (id, timestamps, last/next run)
// are filled by the store.
type ScheduleInput struct {
	Name             string     `json:"name"`
	CronExpr         string     `json:"cronExpr"`
	Timezone         string     `json:"timezone"`
	RunCheck         bool       `json:"runCheck"`
	RunApply         bool       `json:"runApply"`
	RebootAfterApply bool       `json:"rebootAfterApply"`
	TargetKind       TargetKind `json:"targetKind"`
	TargetValue      string     `json:"targetValue"`
	Enabled          bool       `json:"enabled"`
}

// Validate returns ErrInvalid wrapped with a precise reason. Caller
// can errors.Is(err, ErrInvalid) without depending on the message.
// On success, the input's Name/Timezone/CronExpr/TargetValue are
// returned with whitespace trimmed so the caller persists the
// canonical form.
func (in *ScheduleInput) Validate() error {
	in.Name = strings.TrimSpace(in.Name)
	in.CronExpr = strings.TrimSpace(in.CronExpr)
	in.Timezone = strings.TrimSpace(in.Timezone)
	in.TargetValue = strings.TrimSpace(in.TargetValue)

	if in.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if len(in.Name) > maxNameLen {
		return fmt.Errorf("%w: name exceeds %d chars", ErrInvalid, maxNameLen)
	}
	if _, err := ParseCron(in.CronExpr); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	if in.Timezone == "" {
		in.Timezone = "UTC"
	}
	if _, err := time.LoadLocation(in.Timezone); err != nil {
		return fmt.Errorf("%w: timezone %q: %s", ErrInvalid, in.Timezone, err.Error())
	}
	if !in.RunCheck && !in.RunApply {
		return fmt.Errorf("%w: at least one of runCheck/runApply must be true", ErrInvalid)
	}
	if in.RebootAfterApply && !in.RunApply {
		return fmt.Errorf("%w: rebootAfterApply requires runApply", ErrInvalid)
	}
	switch in.TargetKind {
	case TargetGlobal:
		if in.TargetValue != "" {
			return fmt.Errorf("%w: targetValue must be empty when targetKind=global", ErrInvalid)
		}
	case TargetGroup:
		if in.TargetValue == "" {
			return fmt.Errorf("%w: targetValue (group id) is required when targetKind=group", ErrInvalid)
		}
	case TargetSystems:
		var ids []string
		if err := json.Unmarshal([]byte(in.TargetValue), &ids); err != nil {
			return fmt.Errorf("%w: targetValue must be a JSON array of system ids: %s", ErrInvalid, err.Error())
		}
		if len(ids) == 0 {
			return fmt.Errorf("%w: targetValue must contain at least one system id when targetKind=systems", ErrInvalid)
		}
		for _, id := range ids {
			if strings.TrimSpace(id) == "" {
				return fmt.Errorf("%w: targetValue contains an empty system id", ErrInvalid)
			}
		}
	case TargetSelector:
		if in.TargetValue == "" {
			return fmt.Errorf("%w: targetValue (selector expression) is required when targetKind=selector", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: targetKind %q is not one of global/group/systems/selector", ErrInvalid, in.TargetKind)
	}
	return nil
}

// ScheduleRun is one historical execution of a schedule.
type ScheduleRun struct {
	ID               string     `json:"id"`
	ScheduleID       string     `json:"scheduleId"`
	StartedAt        time.Time  `json:"startedAt"`
	FinishedAt       *time.Time `json:"finishedAt,omitempty"`
	Status           RunStatus  `json:"status"`
	TargetsAttempted int        `json:"targetsAttempted"`
	TargetsSucceeded int        `json:"targetsSucceeded"`
	TargetsFailed    int        `json:"targetsFailed"`
	Message          string     `json:"message,omitempty"`
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("schedules: rand.Read: %w", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
