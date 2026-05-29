// SPDX-License-Identifier: Apache-2.0

package exclusions

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/systems"
)

type fixture struct {
	t       *testing.T
	db      *sql.DB
	store   *SQLiteStore
	systems *systems.SQLiteStore
	groups  *groups.SQLiteStore
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "exclusions.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	groupStore, err := groups.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("groups.NewSQLiteStore: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("exclusions.NewSQLiteStore: %v", err)
	}
	var idCount atomic.Int64
	store.NewID = func() string { return fmt.Sprintf("ex-%d", idCount.Add(1)) }
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var tick atomic.Int64
	store.Now = func() time.Time {
		return base.Add(time.Duration(tick.Add(1)) * time.Second)
	}
	return &fixture{t: t, db: db, store: store, systems: sysStore, groups: groupStore}
}

func (f *fixture) mustCreate(scope Scope, target, updater, pattern string) Exclusion {
	f.t.Helper()
	e, err := f.store.Create(scope, target, updater, pattern, "", "actor")
	if err != nil {
		f.t.Fatalf("Create(%s/%s/%s/%s): %v", scope, target, updater, pattern, err)
	}
	return e
}

func TestSQLiteCreateGlobalRoundTrip(t *testing.T) {
	f := newFixture(t)
	e, err := f.store.Create(ScopeGlobal, "", "builtin.dnf", "kernel*", "fleet pin", "actor")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := f.store.Get(e.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Scope != ScopeGlobal || got.TargetID != "" || got.Updater != "builtin.dnf" || got.Pattern != "kernel*" || got.Reason != "fleet pin" || got.CreatedBy != "actor" {
		t.Errorf("Get = %+v", got)
	}
}

func TestSQLiteCreateRejectsTargetMismatch(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.Create(ScopeGlobal, "stray", "builtin.dnf", "kernel", "", "actor"); !errors.Is(err, ErrInvalid) {
		t.Errorf("global+target: err = %v, want ErrInvalid", err)
	}
	if _, err := f.store.Create(ScopeGroup, "", "builtin.dnf", "kernel", "", "actor"); !errors.Is(err, ErrInvalid) {
		t.Errorf("group-no-target: err = %v, want ErrInvalid", err)
	}
	if _, err := f.store.Create(ScopeSystem, "", "builtin.dnf", "kernel", "", "actor"); !errors.Is(err, ErrInvalid) {
		t.Errorf("system-no-target: err = %v, want ErrInvalid", err)
	}
}

func TestSQLiteCreateRejectsDuplicate(t *testing.T) {
	f := newFixture(t)
	f.mustCreate(ScopeGlobal, "", "builtin.dnf", "kernel")
	if _, err := f.store.Create(ScopeGlobal, "", "builtin.dnf", "kernel", "", "actor"); !errors.Is(err, ErrDuplicate) {
		t.Errorf("err = %v, want ErrDuplicate", err)
	}
}

func TestSQLiteCreateRejectsMissingCreatedBy(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.Create(ScopeGlobal, "", "builtin.dnf", "kernel", "", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestSQLiteListByScope(t *testing.T) {
	f := newFixture(t)
	g, err := f.groups.Create(groups.GroupInput{Name: "prod"})
	if err != nil {
		t.Fatalf("group: %v", err)
	}
	h, err := f.systems.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	f.mustCreate(ScopeGlobal, "", "builtin.dnf", "kernel")
	f.mustCreate(ScopeGroup, g.ID, "builtin.dnf", "nginx")
	f.mustCreate(ScopeSystem, h.ID, "builtin.dnf", "redis")

	if rs, _ := f.store.ListGlobal(); len(rs) != 1 || rs[0].Pattern != "kernel" {
		t.Errorf("ListGlobal = %v", rs)
	}
	if rs, _ := f.store.ListGroup(g.ID); len(rs) != 1 || rs[0].Pattern != "nginx" {
		t.Errorf("ListGroup = %v", rs)
	}
	if rs, _ := f.store.ListSystem(h.ID); len(rs) != 1 || rs[0].Pattern != "redis" {
		t.Errorf("ListSystem = %v", rs)
	}
}

func TestSQLiteDeleteMissing(t *testing.T) {
	f := newFixture(t)
	if err := f.store.Delete("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestSQLiteDelete(t *testing.T) {
	f := newFixture(t)
	e := f.mustCreate(ScopeGlobal, "", "builtin.dnf", "kernel")
	if err := f.store.Delete(e.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := f.store.Get(e.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete: err = %v, want ErrNotFound", err)
	}
}

func TestSQLiteResolveForSystemUnion(t *testing.T) {
	f := newFixture(t)
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	other, _ := f.groups.Create(groups.GroupInput{Name: "stage"})
	h, _ := f.systems.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	if err := f.systems.SetGroup(h.ID, &g.ID); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}
	hOther, _ := f.systems.Create(systems.SystemInput{Name: "x", Hostname: "2.2.2.2"})
	if err := f.systems.SetGroup(hOther.ID, &other.ID); err != nil {
		t.Fatalf("SetGroup other: %v", err)
	}

	// Patterns at every scope.
	f.mustCreate(ScopeGlobal, "", "builtin.dnf", "kernel")
	f.mustCreate(ScopeGlobal, "", "*", "vendor-*")              // wildcard updater
	f.mustCreate(ScopeGroup, g.ID, "builtin.dnf", "nginx")      // matching group
	f.mustCreate(ScopeGroup, other.ID, "builtin.dnf", "stray")  // wrong group — must not appear
	f.mustCreate(ScopeSystem, h.ID, "builtin.dnf", "redis")     // matching system
	f.mustCreate(ScopeSystem, hOther.ID, "builtin.dnf", "miss") // wrong system

	patterns, err := f.store.ResolveForSystem(h.ID, "builtin.dnf")
	if err != nil {
		t.Fatalf("ResolveForSystem: %v", err)
	}
	want := []string{"kernel", "nginx", "redis", "vendor-*"}
	if len(patterns) != len(want) {
		t.Fatalf("patterns = %v, want %v", patterns, want)
	}
	for i, w := range want {
		if patterns[i] != w {
			t.Errorf("patterns[%d] = %q, want %q", i, patterns[i], w)
		}
	}
}

func TestSQLiteResolveForSystemDedupes(t *testing.T) {
	f := newFixture(t)
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	h, _ := f.systems.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	if err := f.systems.SetGroup(h.ID, &g.ID); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}
	// Same pattern at three layers — Resolve must deduplicate.
	f.mustCreate(ScopeGlobal, "", "builtin.dnf", "kernel")
	f.mustCreate(ScopeGroup, g.ID, "builtin.dnf", "kernel")
	f.mustCreate(ScopeSystem, h.ID, "builtin.dnf", "kernel")
	got, err := f.store.ResolveForSystem(h.ID, "builtin.dnf")
	if err != nil {
		t.Fatalf("ResolveForSystem: %v", err)
	}
	if len(got) != 1 || got[0] != "kernel" {
		t.Errorf("got = %v, want [kernel]", got)
	}
}

func TestSQLiteResolveEffectiveKeepsScope(t *testing.T) {
	f := newFixture(t)
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	h, _ := f.systems.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	if err := f.systems.SetGroup(h.ID, &g.ID); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}
	f.mustCreate(ScopeGlobal, "", "builtin.dnf", "kernel")
	f.mustCreate(ScopeGroup, g.ID, "builtin.dnf", "kernel")
	rows, err := f.store.ResolveEffectiveForSystem(h.ID, "builtin.dnf")
	if err != nil {
		t.Fatalf("ResolveEffectiveForSystem: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("len = %d, want 2 (effective view keeps both scopes)", len(rows))
	}
	// Global rows sort ahead of group rows by the CASE expression.
	if rows[0].Scope != ScopeGlobal || rows[1].Scope != ScopeGroup {
		t.Errorf("scopes = %s,%s; want global,group", rows[0].Scope, rows[1].Scope)
	}
}

func TestSQLiteResolveSystemWithoutGroupSkipsGroupRows(t *testing.T) {
	f := newFixture(t)
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	h, _ := f.systems.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	// h has no group assignment — group-scope rows must not match.
	f.mustCreate(ScopeGroup, g.ID, "builtin.dnf", "nginx")
	got, err := f.store.ResolveForSystem(h.ID, "builtin.dnf")
	if err != nil {
		t.Fatalf("ResolveForSystem: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got = %v, want [] (no group → no group rows)", got)
	}
}

func TestSQLiteResolveRejectsEmptyArgs(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.ResolveForSystem("", "builtin.dnf"); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty system: err = %v, want ErrInvalid", err)
	}
	if _, err := f.store.ResolveForSystem("sys", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty updater: err = %v, want ErrInvalid", err)
	}
}

func TestIsUniqueViolation(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Error("isUniqueViolation(nil) = true, want false")
	}
	if !isUniqueViolation(errors.New("UNIQUE constraint failed: package_exclusions.id")) {
		t.Error("isUniqueViolation expected message: got false")
	}
	if isUniqueViolation(errors.New("some other error")) {
		t.Error("isUniqueViolation unrelated message: got true")
	}
}

func TestInputValidate(t *testing.T) {
	cases := []struct {
		name    string
		in      Input
		wantErr bool
	}{
		{"missing updater", Input{Pattern: "kernel*"}, true},
		{"bad updater shape", Input{Updater: "no-dot", Pattern: "kernel*"}, true},
		{"missing pattern", Input{Updater: "builtin.dnf"}, true},
		{"pattern too long", Input{Updater: "builtin.dnf", Pattern: strings.Repeat("a", MaxPatternLen+1)}, true},
		{"reason too long", Input{Updater: "builtin.dnf", Pattern: "x*", Reason: strings.Repeat("b", MaxReasonLen+1)}, true},
		{"star updater accepted", Input{Updater: "*", Pattern: "x*"}, false},
		{"custom updater accepted", Input{Updater: "custom.my", Pattern: "x*"}, false},
		{"ok with reason", Input{Updater: "builtin.dnf", Pattern: "kernel*", Reason: "pinned"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.in.Validate()
			if tc.wantErr && err == nil {
				t.Error("Validate = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate = %v, want nil", err)
			}
		})
	}
}

func TestScopeIsValid(t *testing.T) {
	for _, s := range []Scope{ScopeGlobal, ScopeGroup, ScopeSystem} {
		if !s.IsValid() {
			t.Errorf("Scope(%q).IsValid() = false", s)
		}
	}
	if Scope("nonsense").IsValid() {
		t.Error("Scope('nonsense').IsValid() = true")
	}
}

func TestStoreClosedDBSurfacesErrors(t *testing.T) {
	f := newFixture(t)
	if err := f.db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	type call struct {
		name string
		fn   func() error
	}
	calls := []call{
		{"Create", func() error {
			_, err := f.store.Create(ScopeGlobal, "", "builtin.dnf", "x*", "r", "u")
			return err
		}},
		{"Get", func() error { _, err := f.store.Get("ex"); return err }},
		{"Delete", func() error { return f.store.Delete("ex") }},
		{"ListGlobal", func() error { _, err := f.store.ListGlobal(); return err }},
		{"ListGroup", func() error { _, err := f.store.ListGroup("g"); return err }},
		{"ListSystem", func() error { _, err := f.store.ListSystem("s"); return err }},
		{"ResolveForSystem", func() error { _, err := f.store.ResolveForSystem("s", "builtin.dnf"); return err }},
		{"ResolveEffectiveForSystem", func() error {
			_, err := f.store.ResolveEffectiveForSystem("s", "builtin.dnf")
			return err
		}},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(); err == nil {
				t.Errorf("%s on closed DB returned nil error", c.name)
			}
		})
	}
}
