// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "alerts.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return st
}

func TestSchemaIdempotent(t *testing.T) {
	st := newTestStore(t)
	if _, err := NewSQLiteStore(st.db); err != nil {
		t.Fatalf("re-running schema should be a no-op: %v", err)
	}
}

func TestCreateGetListRule(t *testing.T) {
	st := newTestStore(t)
	in := validMetricInput()
	r, err := st.Create(in, "user-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if r.ID == "" || r.CreatedBy != "user-1" || r.CreatedAt.IsZero() {
		t.Errorf("server fields not filled: %+v", r)
	}
	got, err := st.Get(r.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != in.Name || got.Metric != in.Metric || got.Threshold != in.Threshold {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	all, err := st.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("list: %d %v", len(all), err)
	}
}

func TestCreateRejectsInvalidAndNoUser(t *testing.T) {
	st := newTestStore(t)
	bad := validMetricInput()
	bad.Name = ""
	if _, err := st.Create(bad, "u"); !errors.Is(err, ErrInvalid) {
		t.Errorf("expected ErrInvalid, got %v", err)
	}
	if _, err := st.Create(validMetricInput(), ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("expected ErrInvalid for empty createdBy, got %v", err)
	}
}

func TestGetNotFound(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateRule(t *testing.T) {
	st := newTestStore(t)
	r, _ := st.Create(validMetricInput(), "u")
	in := validMetricInput()
	in.Name = "renamed"
	in.Threshold = 80
	updated, err := st.Update(r.ID, in)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "renamed" || updated.Threshold != 80 {
		t.Errorf("update not applied: %+v", updated)
	}
	if _, err := st.Update("missing", in); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestListEnabled(t *testing.T) {
	st := newTestStore(t)
	on := validMetricInput()
	on.Enabled = true
	off := validMetricInput()
	off.Enabled = false
	if _, err := st.Create(on, "u"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(off, "u"); err != nil {
		t.Fatal(err)
	}
	enabled, err := st.ListEnabled()
	if err != nil || len(enabled) != 1 {
		t.Fatalf("ListEnabled = %d %v, want 1", len(enabled), err)
	}
}

func TestDeleteRuleCascadesInstances(t *testing.T) {
	st := newTestStore(t)
	r, _ := st.Create(validMetricInput(), "u")
	now := time.Now().UTC()
	if err := st.PutInstance(Instance{RuleID: r.ID, SystemID: "sys-1", State: StatePending, FirstBreachAt: now, LastEvalAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(r.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	insts, err := st.InstancesForRule(r.ID)
	if err != nil || len(insts) != 0 {
		t.Errorf("instances not cascaded: %d %v", len(insts), err)
	}
	if err := st.Delete(r.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete expected ErrNotFound, got %v", err)
	}
}

func TestUpdateDisablingClearsInstances(t *testing.T) {
	st := newTestStore(t)
	in := validMetricInput()
	in.Enabled = true
	r, _ := st.Create(in, "u")
	now := time.Now().UTC()
	_ = st.PutInstance(Instance{RuleID: r.ID, SystemID: "sys-1", State: StateFiring, FirstBreachAt: now, FiredAt: &now, LastEvalAt: now})
	disabled := validMetricInput()
	disabled.Enabled = false
	if _, err := st.Update(r.ID, disabled); err != nil {
		t.Fatal(err)
	}
	insts, _ := st.InstancesForRule(r.ID)
	if len(insts) != 0 {
		t.Errorf("update to disabled should clear instances, got %d", len(insts))
	}
}

func TestPutInstanceUpsert(t *testing.T) {
	st := newTestStore(t)
	r, _ := st.Create(validMetricInput(), "u")
	now := time.Now().UTC()
	pending := Instance{RuleID: r.ID, SystemID: "s", State: StatePending, Value: 91, FirstBreachAt: now, LastEvalAt: now}
	if err := st.PutInstance(pending); err != nil {
		t.Fatal(err)
	}
	fired := now.Add(5 * time.Minute)
	firing := Instance{RuleID: r.ID, SystemID: "s", State: StateFiring, Value: 95, FirstBreachAt: now, FiredAt: &fired, LastEvalAt: fired}
	if err := st.PutInstance(firing); err != nil {
		t.Fatal(err)
	}
	insts, _ := st.InstancesForRule(r.ID)
	if len(insts) != 1 {
		t.Fatalf("upsert created a duplicate: %d rows", len(insts))
	}
	got := insts[0]
	if got.State != StateFiring || got.Value != 95 || got.FiredAt == nil {
		t.Errorf("upsert did not update fields: %+v", got)
	}
	if !got.FirstBreachAt.Equal(now) {
		t.Errorf("first_breach_at should be preserved: %v", got.FirstBreachAt)
	}
}

func TestDeleteInstance(t *testing.T) {
	st := newTestStore(t)
	r, _ := st.Create(validMetricInput(), "u")
	now := time.Now().UTC()
	_ = st.PutInstance(Instance{RuleID: r.ID, SystemID: "s", State: StatePending, FirstBreachAt: now, LastEvalAt: now})
	if err := st.DeleteInstance(r.ID, "s"); err != nil {
		t.Fatal(err)
	}
	insts, _ := st.InstancesForRule(r.ID)
	if len(insts) != 0 {
		t.Errorf("instance not deleted: %d", len(insts))
	}
	// Deleting an absent instance is a no-op, not an error.
	if err := st.DeleteInstance(r.ID, "s"); err != nil {
		t.Errorf("deleting absent instance should be no-op, got %v", err)
	}
}

func TestListActiveJoinAndOrder(t *testing.T) {
	st := newTestStore(t)
	in := validMetricInput()
	in.Enabled = true
	in.Severity = SeverityCritical
	r, _ := st.Create(in, "u")
	now := time.Now().UTC()
	fired := now.Add(time.Minute)
	_ = st.PutInstance(Instance{RuleID: r.ID, SystemID: "pending-sys", State: StatePending, Value: 91, FirstBreachAt: now, LastEvalAt: now})
	_ = st.PutInstance(Instance{RuleID: r.ID, SystemID: "firing-sys", State: StateFiring, Value: 96, FirstBreachAt: now.Add(time.Second), FiredAt: &fired, LastEvalAt: fired})

	active, err := st.ListActive()
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("want 2 active, got %d", len(active))
	}
	// Firing sorts first.
	if active[0].State != StateFiring || active[0].SystemID != "firing-sys" {
		t.Errorf("firing should sort first: %+v", active[0])
	}
	if active[0].RuleName != in.Name || active[0].Severity != SeverityCritical {
		t.Errorf("rule fields not joined: %+v", active[0])
	}
	if active[0].Metric != MetricMemUsedPct || active[0].Comparator != GreaterThan {
		t.Errorf("condition fields not joined: %+v", active[0])
	}
}

func TestListActiveExcludesDisabledRules(t *testing.T) {
	st := newTestStore(t)
	in := validMetricInput()
	in.Enabled = true
	r, _ := st.Create(in, "u")
	now := time.Now().UTC()
	_ = st.PutInstance(Instance{RuleID: r.ID, SystemID: "s", State: StateFiring, FirstBreachAt: now, FiredAt: &now, LastEvalAt: now})
	// Disabling clears instances, so directly flip the flag without the
	// cascade to prove the JOIN filter also excludes them.
	if _, err := st.db.Exec(`UPDATE alert_rules SET enabled = 0 WHERE id = ?`, r.ID); err != nil {
		t.Fatal(err)
	}
	active, err := st.ListActive()
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Errorf("disabled rule's instances should be excluded, got %d", len(active))
	}
}
