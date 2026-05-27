// SPDX-License-Identifier: Apache-2.0

package holds

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
)

type fixture struct {
	t     *testing.T
	db    *sql.DB
	store *SQLiteStore
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "holds.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	store.Now = func() time.Time { return base }
	return &fixture{t: t, db: db, store: store}
}

func TestListEmptyReturnsEmptySlice(t *testing.T) {
	f := newFixture(t)
	got, err := f.store.List("sys-1", "builtin.apt")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("List() = %v, want empty", got)
	}
}

func TestReplaceInsertsThenList(t *testing.T) {
	f := newFixture(t)
	if err := f.store.Replace("sys-1", "builtin.apt", []string{"vim", "curl", "bash"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got, err := f.store.List("sys-1", "builtin.apt")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"bash", "curl", "vim"}
	if len(got) != len(want) {
		t.Fatalf("List() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("List()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReplaceReplaces(t *testing.T) {
	f := newFixture(t)
	if err := f.store.Replace("sys-1", "builtin.apt", []string{"a", "b", "c"}); err != nil {
		t.Fatalf("Replace 1: %v", err)
	}
	if err := f.store.Replace("sys-1", "builtin.apt", []string{"b", "d"}); err != nil {
		t.Fatalf("Replace 2: %v", err)
	}
	got, _ := f.store.List("sys-1", "builtin.apt")
	want := []string{"b", "d"}
	if len(got) != len(want) {
		t.Fatalf("List() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReplaceEmptyClears(t *testing.T) {
	f := newFixture(t)
	_ = f.store.Replace("sys-1", "builtin.apt", []string{"x", "y"})
	if err := f.store.Replace("sys-1", "builtin.apt", nil); err != nil {
		t.Fatalf("Replace empty: %v", err)
	}
	got, _ := f.store.List("sys-1", "builtin.apt")
	if len(got) != 0 {
		t.Errorf("List after empty Replace = %v, want empty", got)
	}
}

func TestReplaceIsolatesByUpdater(t *testing.T) {
	f := newFixture(t)
	_ = f.store.Replace("sys-1", "builtin.apt", []string{"vim"})
	_ = f.store.Replace("sys-1", "builtin.brew", []string{"jq"})
	apt, _ := f.store.List("sys-1", "builtin.apt")
	brew, _ := f.store.List("sys-1", "builtin.brew")
	if len(apt) != 1 || apt[0] != "vim" {
		t.Errorf("apt = %v", apt)
	}
	if len(brew) != 1 || brew[0] != "jq" {
		t.Errorf("brew = %v", brew)
	}
	// Wiping apt must not touch brew.
	_ = f.store.Replace("sys-1", "builtin.apt", nil)
	brew, _ = f.store.List("sys-1", "builtin.brew")
	if len(brew) != 1 || brew[0] != "jq" {
		t.Errorf("brew after apt wipe = %v", brew)
	}
}

func TestReplaceIsolatesBySystem(t *testing.T) {
	f := newFixture(t)
	_ = f.store.Replace("sys-1", "builtin.apt", []string{"vim"})
	_ = f.store.Replace("sys-2", "builtin.apt", []string{"curl"})
	a, _ := f.store.List("sys-1", "builtin.apt")
	b, _ := f.store.List("sys-2", "builtin.apt")
	if len(a) != 1 || a[0] != "vim" {
		t.Errorf("sys-1 = %v", a)
	}
	if len(b) != 1 || b[0] != "curl" {
		t.Errorf("sys-2 = %v", b)
	}
}

func TestReplaceDeduplicatesAndTrims(t *testing.T) {
	f := newFixture(t)
	in := []string{"  vim ", "vim", "curl", "", "  ", "curl"}
	if err := f.store.Replace("sys-1", "builtin.apt", in); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got, _ := f.store.List("sys-1", "builtin.apt")
	want := []string{"curl", "vim"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRemoveSystemDropsAllRows(t *testing.T) {
	f := newFixture(t)
	_ = f.store.Replace("sys-1", "builtin.apt", []string{"vim", "curl"})
	_ = f.store.Replace("sys-1", "builtin.brew", []string{"jq"})
	_ = f.store.Replace("sys-2", "builtin.apt", []string{"vim"})
	n, err := f.store.RemoveSystem("sys-1")
	if err != nil {
		t.Fatalf("RemoveSystem: %v", err)
	}
	if n != 3 {
		t.Errorf("affected = %d, want 3", n)
	}
	apt, _ := f.store.List("sys-1", "builtin.apt")
	brew, _ := f.store.List("sys-1", "builtin.brew")
	other, _ := f.store.List("sys-2", "builtin.apt")
	if len(apt) != 0 || len(brew) != 0 {
		t.Errorf("sys-1 still has rows: apt=%v brew=%v", apt, brew)
	}
	if len(other) != 1 {
		t.Errorf("sys-2 unexpectedly affected: %v", other)
	}
}

func TestRemoveSystemMissingIsZeroNotError(t *testing.T) {
	f := newFixture(t)
	n, err := f.store.RemoveSystem("ghost")
	if err != nil {
		t.Fatalf("RemoveSystem: %v", err)
	}
	if n != 0 {
		t.Errorf("affected = %d, want 0", n)
	}
}

func TestListRejectsEmptyInput(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.List("", "builtin.apt"); !errors.Is(err, ErrInvalid) {
		t.Errorf("List(\"\",) err = %v, want ErrInvalid", err)
	}
	if _, err := f.store.List("sys-1", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("List(sys-1,\"\") err = %v, want ErrInvalid", err)
	}
}

func TestReplaceRejectsEmptyInput(t *testing.T) {
	f := newFixture(t)
	if err := f.store.Replace("", "builtin.apt", nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("Replace err = %v, want ErrInvalid", err)
	}
	if err := f.store.Replace("sys-1", "", nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("Replace err = %v, want ErrInvalid", err)
	}
}

func TestRemoveSystemRejectsEmpty(t *testing.T) {
	f := newFixture(t)
	if _, err := f.store.RemoveSystem(""); !errors.Is(err, ErrInvalid) {
		t.Errorf("RemoveSystem err = %v, want ErrInvalid", err)
	}
}

func TestNewSQLiteStoreSchemaErrorIsWrapped(t *testing.T) {
	db, err := database.Open("file:" + filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = db.Close()
	if _, err := NewSQLiteStore(db); err == nil {
		t.Errorf("NewSQLiteStore on closed db returned nil; want schema error")
	}
}

func TestStoreOperationsSurfaceDBErrors(t *testing.T) {
	f := newFixture(t)
	_ = f.db.Close()
	if _, err := f.store.List("sys-1", "builtin.apt"); err == nil {
		t.Errorf("List on closed db: err = nil; want error")
	}
	if err := f.store.Replace("sys-1", "builtin.apt", []string{"vim"}); err == nil {
		t.Errorf("Replace on closed db: err = nil; want error")
	}
	if _, err := f.store.RemoveSystem("sys-1"); err == nil {
		t.Errorf("RemoveSystem on closed db: err = nil; want error")
	}
}

func TestNowDefaultsToCurrentTime(t *testing.T) {
	f := newFixture(t)
	f.store.Now = nil
	before := time.Now().UTC().Add(-time.Second)
	if err := f.store.Replace("sys-1", "builtin.apt", []string{"vim"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	var setAt int64
	if err := f.db.QueryRow(
		`SELECT set_at FROM managed_holds WHERE system_id = ? AND updater = ? AND pattern = ?`,
		"sys-1", "builtin.apt", "vim",
	).Scan(&setAt); err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	got := time.Unix(0, setAt).UTC()
	if got.Before(before) {
		t.Errorf("set_at %v earlier than before=%v", got, before)
	}
}
