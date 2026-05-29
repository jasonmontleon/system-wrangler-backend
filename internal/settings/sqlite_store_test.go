// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"errors"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/database"
)

func newStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "settings.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return store
}

func TestSetAndGetRoundTrip(t *testing.T) {
	store := newStore(t)
	if _, err := store.Get("nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing key: err = %v, want ErrNotFound", err)
	}
	if err := store.Set("key", "value"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	v, err := store.Get("key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if v != "value" {
		t.Errorf("Get = %q, want value", v)
	}
	// Update overwrites.
	if err := store.Set("key", "value2"); err != nil {
		t.Fatalf("Set update: %v", err)
	}
	v, _ = store.Get("key")
	if v != "value2" {
		t.Errorf("Get after update = %q, want value2", v)
	}
}

func TestSetRejectsEmptyKey(t *testing.T) {
	store := newStore(t)
	if err := store.Set("", "x"); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestAllReturnsEverySetting(t *testing.T) {
	store := newStore(t)
	if err := store.Set("a", "1"); err != nil {
		t.Fatalf("Set a: %v", err)
	}
	if err := store.Set("b", "2"); err != nil {
		t.Fatalf("Set b: %v", err)
	}
	all, err := store.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(all) != 2 || all["a"] != "1" || all["b"] != "2" {
		t.Errorf("All = %v, want map[a:1 b:2]", all)
	}
}

func TestRunHistoryLimitFallback(t *testing.T) {
	store := newStore(t)
	// Unset → default.
	if got := RunHistoryLimit(store); got != DefaultRunHistoryLimit {
		t.Errorf("unset: got %d, want %d", got, DefaultRunHistoryLimit)
	}
	// Unparseable → default.
	if err := store.Set(KeyRunHistoryLimit, "junk"); err != nil {
		t.Fatalf("Set junk: %v", err)
	}
	if got := RunHistoryLimit(store); got != DefaultRunHistoryLimit {
		t.Errorf("junk: got %d, want %d", got, DefaultRunHistoryLimit)
	}
	// Out-of-range low → default (the accessor refuses below the floor).
	if err := store.Set(KeyRunHistoryLimit, "0"); err != nil {
		t.Fatalf("Set 0: %v", err)
	}
	if got := RunHistoryLimit(store); got != DefaultRunHistoryLimit {
		t.Errorf("0: got %d, want %d", got, DefaultRunHistoryLimit)
	}
	// Above the ceiling → clamped to MaxRunHistoryLimit.
	if err := store.Set(KeyRunHistoryLimit, "99999"); err != nil {
		t.Fatalf("Set huge: %v", err)
	}
	if got := RunHistoryLimit(store); got != MaxRunHistoryLimit {
		t.Errorf("huge: got %d, want %d", got, MaxRunHistoryLimit)
	}
	// Nil store → default.
	if got := RunHistoryLimit(nil); got != DefaultRunHistoryLimit {
		t.Errorf("nil store: got %d, want %d", got, DefaultRunHistoryLimit)
	}
}

func TestSetRunHistoryLimitValidation(t *testing.T) {
	store := newStore(t)
	if err := SetRunHistoryLimit(store, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero: err = %v, want ErrInvalid", err)
	}
	if err := SetRunHistoryLimit(store, MaxRunHistoryLimit+1); !errors.Is(err, ErrInvalid) {
		t.Errorf("over max: err = %v, want ErrInvalid", err)
	}
	if err := SetRunHistoryLimit(store, 250); err != nil {
		t.Errorf("valid: err = %v, want nil", err)
	}
	if got := RunHistoryLimit(store); got != 250 {
		t.Errorf("RunHistoryLimit = %d, want 250", got)
	}
}

func TestUpdateConcurrencyLimitFallback(t *testing.T) {
	store := newStore(t)
	if got := UpdateConcurrencyLimit(store); got != DefaultUpdateConcurrencyLimit {
		t.Errorf("unset: got %d, want %d", got, DefaultUpdateConcurrencyLimit)
	}
	if err := store.Set(KeyUpdateConcurrencyLimit, "junk"); err != nil {
		t.Fatalf("Set junk: %v", err)
	}
	if got := UpdateConcurrencyLimit(store); got != DefaultUpdateConcurrencyLimit {
		t.Errorf("junk: got %d, want %d", got, DefaultUpdateConcurrencyLimit)
	}
	if err := store.Set(KeyUpdateConcurrencyLimit, "0"); err != nil {
		t.Fatalf("Set 0: %v", err)
	}
	if got := UpdateConcurrencyLimit(store); got != DefaultUpdateConcurrencyLimit {
		t.Errorf("0: got %d, want %d", got, DefaultUpdateConcurrencyLimit)
	}
	if err := store.Set(KeyUpdateConcurrencyLimit, "9999"); err != nil {
		t.Fatalf("Set huge: %v", err)
	}
	if got := UpdateConcurrencyLimit(store); got != MaxUpdateConcurrencyLimit {
		t.Errorf("huge: got %d, want %d", got, MaxUpdateConcurrencyLimit)
	}
	if got := UpdateConcurrencyLimit(nil); got != DefaultUpdateConcurrencyLimit {
		t.Errorf("nil store: got %d, want %d", got, DefaultUpdateConcurrencyLimit)
	}
}

func TestSetUpdateConcurrencyLimitValidation(t *testing.T) {
	store := newStore(t)
	if err := SetUpdateConcurrencyLimit(store, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero: err = %v, want ErrInvalid", err)
	}
	if err := SetUpdateConcurrencyLimit(store, MaxUpdateConcurrencyLimit+1); !errors.Is(err, ErrInvalid) {
		t.Errorf("over max: err = %v, want ErrInvalid", err)
	}
	if err := SetUpdateConcurrencyLimit(store, 8); err != nil {
		t.Errorf("valid: err = %v, want nil", err)
	}
	if got := UpdateConcurrencyLimit(store); got != 8 {
		t.Errorf("UpdateConcurrencyLimit = %d, want 8", got)
	}
}

func TestStoreClosedDBSurfacesErrors(t *testing.T) {
	dsn := "file:" + t.TempDir() + "/settings-closed.db"
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	type call struct {
		name string
		fn   func() error
	}
	calls := []call{
		{"Get", func() error { _, err := store.Get("k"); return err }},
		{"Set", func() error { return store.Set("k", "v") }},
		{"All", func() error { _, err := store.All(); return err }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(); err == nil {
				t.Errorf("%s on closed DB returned nil error", c.name)
			}
		})
	}
}
