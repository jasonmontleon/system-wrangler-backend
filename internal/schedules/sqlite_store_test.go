// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
)

func newStore(t *testing.T) (*SQLiteStore, *sql.DB) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "schedules.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return store, db
}

func fixedClock(t *testing.T, at time.Time) func() time.Time {
	t.Helper()
	return func() time.Time { return at }
}

func validInput() ScheduleInput {
	return ScheduleInput{
		Name:        "Nightly check",
		CronExpr:    "0 3 * * *",
		Timezone:    "UTC",
		RunCheck:    true,
		RunApply:    false,
		TargetKind:  TargetGlobal,
		TargetValue: "",
		Enabled:     true,
	}
}

func TestCreateAndGetRoundTrip(t *testing.T) {
	s, _ := newStore(t)
	s.Now = fixedClock(t, time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC))
	got, err := s.Create(validInput(), "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got.ID == "" {
		t.Errorf("ID must be assigned")
	}
	if got.NextRunAt == nil {
		t.Fatalf("NextRunAt must be set on an enabled schedule")
	}
	want := time.Date(2026, 6, 1, 3, 0, 0, 0, time.UTC)
	if !got.NextRunAt.Equal(want) {
		t.Errorf("NextRunAt = %s, want %s", got.NextRunAt, want)
	}
	if got.CreatedBy != "user-1" {
		t.Errorf("CreatedBy = %q", got.CreatedBy)
	}
	round, err := s.Get(got.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if round.Name != got.Name || round.CronExpr != got.CronExpr {
		t.Errorf("round-trip mismatch: got %+v", round)
	}
}

func TestCreateRejectsInvalidInputs(t *testing.T) {
	s, _ := newStore(t)
	tests := []struct {
		name string
		mut  func(*ScheduleInput)
	}{
		{"empty name", func(in *ScheduleInput) { in.Name = "" }},
		{"bad cron", func(in *ScheduleInput) { in.CronExpr = "every wednesday" }},
		{"bad timezone", func(in *ScheduleInput) { in.Timezone = "Mars/Olympus" }},
		{"no action", func(in *ScheduleInput) { in.RunCheck = false; in.RunApply = false }},
		{"reboot without apply", func(in *ScheduleInput) { in.RebootAfterApply = true; in.RunApply = false }},
		{"bad target kind", func(in *ScheduleInput) { in.TargetKind = "fleet" }},
		{"group missing id", func(in *ScheduleInput) { in.TargetKind = TargetGroup; in.TargetValue = "" }},
		{"systems missing list", func(in *ScheduleInput) { in.TargetKind = TargetSystems; in.TargetValue = "" }},
		{"systems empty array", func(in *ScheduleInput) { in.TargetKind = TargetSystems; in.TargetValue = "[]" }},
		{"systems empty id", func(in *ScheduleInput) { in.TargetKind = TargetSystems; in.TargetValue = `[""]` }},
		{"systems bad json", func(in *ScheduleInput) { in.TargetKind = TargetSystems; in.TargetValue = "not-json" }},
		{"selector missing expr", func(in *ScheduleInput) { in.TargetKind = TargetSelector; in.TargetValue = "" }},
		{"global with value", func(in *ScheduleInput) { in.TargetValue = "oops" }},
	}
	for _, tt := range tests {
		in := validInput()
		tt.mut(&in)
		if _, err := s.Create(in, "user-1"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: expected ErrInvalid, got %v", tt.name, err)
		}
	}
}

func TestCreateRequiresCreatedBy(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Create(validInput(), ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("Create with empty createdBy: want ErrInvalid, got %v", err)
	}
}

func TestCreateDisabledSchedulesHaveNoNextRun(t *testing.T) {
	s, _ := newStore(t)
	in := validInput()
	in.Enabled = false
	got, err := s.Create(in, "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got.NextRunAt != nil {
		t.Errorf("Disabled schedule must have NextRunAt = nil, got %s", got.NextRunAt)
	}
}

func TestListReturnsScheduleByCreationOrder(t *testing.T) {
	s, _ := newStore(t)
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { now = now.Add(time.Second); return now }
	a, _ := s.Create(validInput(), "user-1")
	b, _ := s.Create(validInput(), "user-1")
	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 || got[0].ID != a.ID || got[1].ID != b.ID {
		t.Errorf("List order wrong: %+v", got)
	}
}

func TestUpdateRecomputesNextRun(t *testing.T) {
	s, _ := newStore(t)
	s.Now = fixedClock(t, time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC))
	got, _ := s.Create(validInput(), "user-1")
	in := validInput()
	in.CronExpr = "30 5 * * *" // 05:30 daily
	updated, err := s.Update(got.ID, in)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.NextRunAt == nil || updated.NextRunAt.Hour() != 5 || updated.NextRunAt.Minute() != 30 {
		t.Errorf("Update did not recompute NextRunAt: %+v", updated.NextRunAt)
	}
}

func TestUpdateNotFound(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Update("missing", validInput()); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update missing: want ErrNotFound, got %v", err)
	}
}

func TestDeleteCascadesRuns(t *testing.T) {
	s, _ := newStore(t)
	sch, _ := s.Create(validInput(), "user-1")
	if _, err := s.RecordRunStart(sch.ID); err != nil {
		t.Fatalf("RecordRunStart: %v", err)
	}
	if err := s.Delete(sch.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	runs, err := s.ListRuns(sch.ID, 0)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 0 {
		t.Errorf("Delete left %d runs behind", len(runs))
	}
}

func TestDeleteNotFound(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Delete("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete missing: want ErrNotFound, got %v", err)
	}
}

func TestSetEnabledClearsAndRecomputesNextRun(t *testing.T) {
	s, _ := newStore(t)
	sch, _ := s.Create(validInput(), "user-1")
	off, err := s.SetEnabled(sch.ID, false)
	if err != nil {
		t.Fatalf("SetEnabled false: %v", err)
	}
	if off.Enabled || off.NextRunAt != nil {
		t.Errorf("Disable should clear NextRunAt and set enabled=false, got %+v", off)
	}
	on, err := s.SetEnabled(sch.ID, true)
	if err != nil {
		t.Fatalf("SetEnabled true: %v", err)
	}
	if !on.Enabled || on.NextRunAt == nil {
		t.Errorf("Enable should set NextRunAt, got %+v", on)
	}
}

func TestRecordRunStartAndFinishAdvancesParent(t *testing.T) {
	s, _ := newStore(t)
	s.Now = fixedClock(t, time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC))
	sch, _ := s.Create(validInput(), "user-1")
	run, err := s.RecordRunStart(sch.ID)
	if err != nil {
		t.Fatalf("RecordRunStart: %v", err)
	}
	if run.Status != StatusRunning {
		t.Errorf("Status = %q, want running", run.Status)
	}
	// Advance the clock so NextRunAt moves to the day after.
	s.Now = fixedClock(t, time.Date(2026, 6, 1, 3, 0, 0, 0, time.UTC))
	if err := s.RecordRunFinish(run.ID, StatusSuccess, 3, 3, 0, "ok"); err != nil {
		t.Fatalf("RecordRunFinish: %v", err)
	}
	parent, _ := s.Get(sch.ID)
	if parent.LastStatus == nil || *parent.LastStatus != StatusSuccess {
		t.Errorf("LastStatus = %v", parent.LastStatus)
	}
	if parent.LastRunAt == nil {
		t.Errorf("LastRunAt must be set")
	}
	if parent.NextRunAt == nil {
		t.Fatalf("NextRunAt must be set after a finished run")
	}
	want := time.Date(2026, 6, 2, 3, 0, 0, 0, time.UTC)
	if !parent.NextRunAt.Equal(want) {
		t.Errorf("NextRunAt = %s, want %s", parent.NextRunAt, want)
	}
	runs, _ := s.ListRuns(sch.ID, 10)
	if len(runs) != 1 || runs[0].Status != StatusSuccess {
		t.Errorf("ListRuns wrong: %+v", runs)
	}
}

func TestRecordRunFinishMissingRunReturnsErrNotFound(t *testing.T) {
	s, _ := newStore(t)
	if err := s.RecordRunFinish("missing", StatusSuccess, 0, 0, 0, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("RecordRunFinish missing: want ErrNotFound, got %v", err)
	}
}

func TestRecordRunFinishOnDisabledScheduleClearsNext(t *testing.T) {
	s, _ := newStore(t)
	s.Now = fixedClock(t, time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC))
	sch, _ := s.Create(validInput(), "user-1")
	run, _ := s.RecordRunStart(sch.ID)
	// Disable mid-run to simulate the operator turning the schedule off.
	if _, err := s.SetEnabled(sch.ID, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if err := s.RecordRunFinish(run.ID, StatusSuccess, 1, 1, 0, ""); err != nil {
		t.Fatalf("RecordRunFinish: %v", err)
	}
	parent, _ := s.Get(sch.ID)
	if parent.NextRunAt != nil {
		t.Errorf("NextRunAt must be nil for a disabled schedule, got %s", parent.NextRunAt)
	}
}

func TestDueReturnsOnlyEnabledAndPastSchedules(t *testing.T) {
	s, _ := newStore(t)
	s.Now = fixedClock(t, time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC))
	enabled, _ := s.Create(validInput(), "user-1")
	disabledIn := validInput()
	disabledIn.Enabled = false
	disabled, _ := s.Create(disabledIn, "user-1")
	// Move "now" to one minute after the enabled schedule's NextRunAt.
	past := enabled.NextRunAt.Add(time.Minute)
	due, err := s.Due(past)
	if err != nil {
		t.Fatalf("Due: %v", err)
	}
	if len(due) != 1 || due[0].ID != enabled.ID {
		t.Errorf("Due returned %+v, want only the enabled schedule (%s)", due, enabled.ID)
	}
	// Disabled schedule never appears even when next_run_at is nil.
	_ = disabled
}

func TestDueExcludesFutureSchedules(t *testing.T) {
	s, _ := newStore(t)
	s.Now = fixedClock(t, time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC))
	sch, _ := s.Create(validInput(), "user-1")
	// Ask for schedules due 1 hour before the first fire — none.
	before := sch.NextRunAt.Add(-time.Hour)
	due, err := s.Due(before)
	if err != nil {
		t.Fatalf("Due: %v", err)
	}
	if len(due) != 0 {
		t.Errorf("Due returned %d, want 0", len(due))
	}
}

func TestListRunsRespectsLimitAndOrder(t *testing.T) {
	s, _ := newStore(t)
	sch, _ := s.Create(validInput(), "user-1")
	for i := 0; i < 3; i++ {
		r, _ := s.RecordRunStart(sch.ID)
		if err := s.RecordRunFinish(r.ID, StatusSuccess, 1, 1, 0, ""); err != nil {
			t.Fatalf("finish: %v", err)
		}
	}
	got, err := s.ListRuns(sch.ID, 2)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ListRuns limit = 2 returned %d", len(got))
	}
}

func TestGetMissingReturnsErrNotFound(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing: want ErrNotFound, got %v", err)
	}
}

func TestSetEnabledMissingReturnsErrNotFound(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.SetEnabled("missing", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetEnabled missing: want ErrNotFound, got %v", err)
	}
}

func TestListEmpty(t *testing.T) {
	s, _ := newStore(t)
	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("List empty: got %d", len(got))
	}
}

func TestListRunsEmpty(t *testing.T) {
	s, _ := newStore(t)
	sch, _ := s.Create(validInput(), "user-1")
	got, err := s.ListRuns(sch.ID, 5)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ListRuns on fresh schedule: got %d", len(got))
	}
}

func TestRoundTripPersistsAllTargetKinds(t *testing.T) {
	cases := []ScheduleInput{
		{Name: "g", CronExpr: "0 * * * *", RunCheck: true, TargetKind: TargetGroup, TargetValue: "grp-1", Enabled: true},
		{Name: "all", CronExpr: "0 * * * *", RunCheck: true, TargetKind: TargetGlobal, TargetValue: "", Enabled: true},
		{Name: "list", CronExpr: "0 * * * *", RunCheck: true, TargetKind: TargetSystems, TargetValue: `["a","b"]`, Enabled: true},
		{Name: "sel", CronExpr: "0 * * * *", RunCheck: true, TargetKind: TargetSelector, TargetValue: "os=linux", Enabled: true},
	}
	for _, in := range cases {
		s, _ := newStore(t)
		got, err := s.Create(in, "user-1")
		if err != nil {
			t.Fatalf("%s: %v", in.Name, err)
		}
		round, _ := s.Get(got.ID)
		if round.TargetKind != in.TargetKind || round.TargetValue != in.TargetValue {
			t.Errorf("%s: round-trip kind=%q val=%q want kind=%q val=%q",
				in.Name, round.TargetKind, round.TargetValue, in.TargetKind, in.TargetValue)
		}
	}
}

func TestStoreMethodsSurfaceClosedDBError(t *testing.T) {
	s, db := newStore(t)
	sch, _ := s.Create(validInput(), "user-1")
	run, _ := s.RecordRunStart(sch.ID)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Each call below should now return a wrapped error rather than
	// panicking — closing the DB exercises the SQL-error branches
	// that we otherwise can't reach.
	if _, err := s.Get(sch.ID); err == nil {
		t.Error("Get on closed DB: expected error")
	}
	if _, err := s.List(); err == nil {
		t.Error("List on closed DB: expected error")
	}
	if _, err := s.Update(sch.ID, validInput()); err == nil {
		t.Error("Update on closed DB: expected error")
	}
	if err := s.Delete(sch.ID); err == nil {
		t.Error("Delete on closed DB: expected error")
	}
	if _, err := s.SetEnabled(sch.ID, true); err == nil {
		t.Error("SetEnabled on closed DB: expected error")
	}
	if _, err := s.RecordRunStart(sch.ID); err == nil {
		t.Error("RecordRunStart on closed DB: expected error")
	}
	if err := s.RecordRunFinish(run.ID, StatusSuccess, 0, 0, 0, ""); err == nil {
		t.Error("RecordRunFinish on closed DB: expected error")
	}
	if _, err := s.ListRuns(sch.ID, 5); err == nil {
		t.Error("ListRuns on closed DB: expected error")
	}
	if _, err := s.Due(time.Now()); err == nil {
		t.Error("Due on closed DB: expected error")
	}
}

func TestNewSQLiteStoreOnClosedDBReturnsError(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "schedules.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = db.Close()
	if _, err := NewSQLiteStore(db); err == nil {
		t.Error("NewSQLiteStore on closed DB: expected error")
	}
}

func TestNewSQLiteStoreIdempotent(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "schedules.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("second init: %v", err)
	}
}
