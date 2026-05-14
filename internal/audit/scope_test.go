// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/systems"
)

// scopeFixture brings up an audit store on a DB that ALSO has the
// hosts table (owned by systems), since the scope filter's
// target_kind='system' branch joins against hosts. Test rows are
// inserted directly with raw SQL so we can control target_id values.
type scopeFixture struct {
	store   *Store
	systems *systems.SQLiteStore
}

func newScopeFixture(t *testing.T) scopeFixture {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit_scope.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sys, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit.NewSQLiteStore: %v", err)
	}
	return scopeFixture{store: store, systems: sys}
}

// mustSystemInGroup creates a host row and stamps it with group_id directly
// so we can build the (system → group) link the scope filter joins on.
func (f scopeFixture) mustSystemInGroup(t *testing.T, name, groupID string) systems.System {
	t.Helper()
	h, err := f.systems.Create(systems.SystemInput{Name: name, Hostname: name + ".local"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	if err := f.systems.SetGroup(h.ID, &groupID); err != nil {
		t.Fatalf("systems.SetGroup: %v", err)
	}
	return h
}

func (f scopeFixture) mustLog(t *testing.T, e Event) {
	t.Helper()
	if err := f.store.Log(context.Background(), e); err != nil {
		t.Fatalf("Log: %v", err)
	}
}

func TestScopeFilter_OnlyVisibleSystemRows(t *testing.T) {
	f := newScopeFixture(t)
	mine := f.mustSystemInGroup(t, "in-scope", "g1")
	theirs := f.mustSystemInGroup(t, "out-of-scope", "g2")
	f.mustLog(t, Event{Action: "system.create", Outcome: Success, TargetKind: "system", TargetID: mine.ID})
	f.mustLog(t, Event{Action: "system.create", Outcome: Success, TargetKind: "system", TargetID: theirs.ID})

	recs, _, err := f.store.ListQuery(Query{Scope: &ScopeFilter{GroupIDs: []string{"g1"}}})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(recs) != 1 || recs[0].TargetID != mine.ID {
		t.Errorf("recs = %+v, want only %s visible", recs, mine.ID)
	}
}

func TestScopeFilter_GroupTargetRows(t *testing.T) {
	f := newScopeFixture(t)
	f.mustLog(t, Event{Action: "system_group.create", Outcome: Success, TargetKind: "system_group", TargetID: "g1"})
	f.mustLog(t, Event{Action: "system_group.create", Outcome: Success, TargetKind: "system_group", TargetID: "g2"})

	recs, _, err := f.store.ListQuery(Query{Scope: &ScopeFilter{GroupIDs: []string{"g1"}}})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(recs) != 1 || recs[0].TargetID != "g1" {
		t.Errorf("recs = %+v, want only g1 visible", recs)
	}
}

func TestScopeFilter_HidesUserTargetRows(t *testing.T) {
	f := newScopeFixture(t)
	mine := f.mustSystemInGroup(t, "in", "g1")
	f.mustLog(t, Event{Action: "system.create", Outcome: Success, TargetKind: "system", TargetID: mine.ID})
	f.mustLog(t, Event{Action: "user.create", Outcome: Success, TargetKind: "user", TargetID: "u1"})

	recs, _, err := f.store.ListQuery(Query{Scope: &ScopeFilter{GroupIDs: []string{"g1"}}})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	for _, r := range recs {
		if r.TargetKind == "user" {
			t.Errorf("user-target row %+v leaked through scope filter", r)
		}
	}
	if len(recs) != 1 {
		t.Errorf("recs = %+v, want only the system row", recs)
	}
}

func TestScopeFilter_DeletedSystemRowHiddenFromGroupOnly(t *testing.T) {
	f := newScopeFixture(t)
	mine := f.mustSystemInGroup(t, "alive", "g1")
	gone, err := f.systems.Create(systems.SystemInput{Name: "deleted", Hostname: "gone.local"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	gid := "g1"
	if err := f.systems.SetGroup(gone.ID, &gid); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}
	f.mustLog(t, Event{Action: "system.create", Outcome: Success, TargetKind: "system", TargetID: mine.ID})
	f.mustLog(t, Event{Action: "system.delete", Outcome: Success, TargetKind: "system", TargetID: gone.ID})
	if err := f.systems.Delete(gone.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// After the system delete, the delete-event row references an id
	// that no longer exists in hosts — the join naturally excludes it.
	recs, _, err := f.store.ListQuery(Query{Scope: &ScopeFilter{GroupIDs: []string{"g1"}}})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(recs) != 1 || recs[0].TargetID != mine.ID {
		t.Errorf("recs = %+v, want only the surviving system", recs)
	}
}

func TestScopeFilter_EmptyGroupsMatchesNothing(t *testing.T) {
	f := newScopeFixture(t)
	mine := f.mustSystemInGroup(t, "in", "g1")
	f.mustLog(t, Event{Action: "system.create", Outcome: Success, TargetKind: "system", TargetID: mine.ID})
	recs, _, err := f.store.ListQuery(Query{Scope: &ScopeFilter{GroupIDs: nil}})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("recs = %+v, want empty for user with no scope groups", recs)
	}
}

func TestScopeFilter_NilDisablesFiltering(t *testing.T) {
	f := newScopeFixture(t)
	f.mustLog(t, Event{Action: "user.create", Outcome: Success, TargetKind: "user", TargetID: "u1"})
	recs, _, err := f.store.ListQuery(Query{Scope: nil})
	if err != nil {
		t.Fatalf("ListQuery: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("recs = %+v, want all rows when Scope is nil", recs)
	}
}

func TestIsVisibleTo(t *testing.T) {
	f := newScopeFixture(t)
	mine := f.mustSystemInGroup(t, "mine", "g1")
	theirs := f.mustSystemInGroup(t, "theirs", "g2")
	sf := ScopeFilter{GroupIDs: []string{"g1"}}

	cases := []struct {
		name string
		rec  Record
		want bool
	}{
		{"my system", Record{TargetKind: "system", TargetID: mine.ID}, true},
		{"their system", Record{TargetKind: "system", TargetID: theirs.ID}, false},
		{"unknown system", Record{TargetKind: "system", TargetID: "ghost"}, false},
		{"my group", Record{TargetKind: "system_group", TargetID: "g1"}, true},
		{"other group", Record{TargetKind: "system_group", TargetID: "g2"}, false},
		{"user-target row", Record{TargetKind: "user", TargetID: "u1"}, false},
		{"empty target", Record{TargetKind: "system", TargetID: ""}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := f.store.IsVisibleTo(tc.rec, sf)
			if err != nil {
				t.Fatalf("IsVisibleTo: %v", err)
			}
			if got != tc.want {
				t.Errorf("IsVisibleTo = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsVisibleTo_EmptyScopeHidesEverything(t *testing.T) {
	f := newScopeFixture(t)
	mine := f.mustSystemInGroup(t, "mine", "g1")
	sf := ScopeFilter{GroupIDs: nil}
	got, err := f.store.IsVisibleTo(Record{TargetKind: "system", TargetID: mine.ID}, sf)
	if err != nil {
		t.Fatalf("IsVisibleTo: %v", err)
	}
	if got {
		t.Error("empty scope.GroupIDs must hide every row")
	}
}
