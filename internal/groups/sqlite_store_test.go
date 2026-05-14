// SPDX-License-Identifier: Apache-2.0

package groups

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/systems"
)

func newSQLiteFixture(t *testing.T) (*sql.DB, *SQLiteStore, *systems.SQLiteStore) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "groups.db")
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
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	var counter atomic.Int64
	store.NewID = func() string { return fmt.Sprintf("gid-%d", counter.Add(1)) }
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var tick atomic.Int64
	store.Now = func() time.Time {
		return base.Add(time.Duration(tick.Add(1)) * time.Second)
	}
	return db, store, sys
}

func TestSQLiteCreateRoundTrip(t *testing.T) {
	_, store, _ := newSQLiteFixture(t)
	g, err := store.Create(GroupInput{Name: "prod"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := store.Get(g.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "prod" || got.SystemCount != 0 {
		t.Errorf("Get = %+v, want name=prod count=0", got)
	}
}

func TestSQLiteCreateRejectsDuplicate(t *testing.T) {
	_, store, _ := newSQLiteFixture(t)
	if _, err := store.Create(GroupInput{Name: "prod"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.Create(GroupInput{Name: "prod"}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("err = %v, want ErrDuplicate", err)
	}
}

func TestSQLiteListPopulatesCount(t *testing.T) {
	_, store, sys := newSQLiteFixture(t)
	g, _ := store.Create(GroupInput{Name: "prod"})
	for i := 0; i < 3; i++ {
		h, err := sys.Create(systems.SystemInput{Name: fmt.Sprintf("h%d", i), Hostname: "1.1.1.1"})
		if err != nil {
			t.Fatalf("systems Create: %v", err)
		}
		if err := sys.SetGroup(h.ID, &g.ID); err != nil {
			t.Fatalf("SetGroup: %v", err)
		}
	}
	got, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].SystemCount != 3 {
		t.Errorf("SystemCount = %d, want 3", got[0].SystemCount)
	}
}

func TestSQLiteRenameRejectsDuplicate(t *testing.T) {
	_, store, _ := newSQLiteFixture(t)
	a, _ := store.Create(GroupInput{Name: "a"})
	if _, err := store.Create(GroupInput{Name: "b"}); err != nil {
		t.Fatalf("Create b: %v", err)
	}
	if _, err := store.Rename(a.ID, GroupInput{Name: "b"}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("err = %v, want ErrDuplicate", err)
	}
}

func TestSQLiteDeleteCascadesToSystems(t *testing.T) {
	_, store, sys := newSQLiteFixture(t)
	g, _ := store.Create(GroupInput{Name: "prod"})
	h, _ := sys.Create(systems.SystemInput{Name: "h", Hostname: "1.1.1.1"})
	if err := sys.SetGroup(h.ID, &g.ID); err != nil {
		t.Fatalf("SetGroup: %v", err)
	}
	if err := store.Delete(g.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, err := sys.Get(h.ID)
	if err != nil {
		t.Fatalf("systems Get: %v", err)
	}
	if got.GroupID != nil {
		t.Errorf("after group delete GroupID = %v, want nil", got.GroupID)
	}
}

func TestSQLiteDeleteMissing(t *testing.T) {
	_, store, _ := newSQLiteFixture(t)
	if err := store.Delete("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestSQLiteRenameMissing(t *testing.T) {
	_, store, _ := newSQLiteFixture(t)
	if _, err := store.Rename("nope", GroupInput{Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestSQLiteGetMissing(t *testing.T) {
	_, store, _ := newSQLiteFixture(t)
	if _, err := store.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestSQLiteRenameRoundTrip(t *testing.T) {
	_, store, _ := newSQLiteFixture(t)
	g, _ := store.Create(GroupInput{Name: "old"})
	renamed, err := store.Rename(g.ID, GroupInput{Name: "new"})
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if renamed.Name != "new" {
		t.Errorf("Name = %q, want 'new'", renamed.Name)
	}
	got, _ := store.Get(g.ID)
	if got.Name != "new" {
		t.Errorf("after Rename Get name = %q", got.Name)
	}
}

func TestSQLiteCreateInvalid(t *testing.T) {
	_, store, _ := newSQLiteFixture(t)
	if _, err := store.Create(GroupInput{Name: ""}); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestSQLiteRenameInvalid(t *testing.T) {
	_, store, _ := newSQLiteFixture(t)
	g, _ := store.Create(GroupInput{Name: "x"})
	if _, err := store.Rename(g.ID, GroupInput{Name: ""}); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestIsUniqueViolationOnNil(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Error("isUniqueViolation(nil) = true, want false")
	}
}
