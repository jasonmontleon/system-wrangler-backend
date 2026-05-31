// SPDX-License-Identifier: Apache-2.0

package dashboardlayout

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/database"
)

func newStore(t *testing.T) (*SQLiteStore, *sql.DB) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "dashboardlayout.db")
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

func TestSQLiteStore_GetSet(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Get("u1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on empty: want ErrNotFound, got %v", err)
	}
	if err := s.Set("u1", `[{"id":"system-health","enabled":true}]`); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get("u1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != `[{"id":"system-health","enabled":true}]` {
		t.Errorf("Get = %q", got)
	}
}

func TestSQLiteStore_SetIsIdempotent(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Set("u1", `[]`); err != nil {
		t.Fatalf("Set v1: %v", err)
	}
	if err := s.Set("u1", `[{"id":"backend-health","enabled":false}]`); err != nil {
		t.Fatalf("Set v2: %v", err)
	}
	got, _ := s.Get("u1")
	if got != `[{"id":"backend-health","enabled":false}]` {
		t.Errorf("Get after overwrite = %q", got)
	}
}

func TestSQLiteStore_SetRequiresUserID(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Set("", `[]`); err == nil {
		t.Error("Set with empty user_id: want error, got nil")
	}
}

func TestSQLiteStore_PerUserIsolation(t *testing.T) {
	s, _ := newStore(t)
	if err := s.Set("alice", `["a"]`); err != nil {
		t.Fatalf("Set alice: %v", err)
	}
	if err := s.Set("bob", `["b"]`); err != nil {
		t.Fatalf("Set bob: %v", err)
	}
	a, _ := s.Get("alice")
	b, _ := s.Get("bob")
	if a == b {
		t.Errorf("alice and bob share layout: %q", a)
	}
}

func TestSQLiteStore_DeleteByUserTx(t *testing.T) {
	s, db := newStore(t)
	if err := s.Set("u1", `[]`); err != nil {
		t.Fatalf("Set: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := s.DeleteByUserTx(tx, "u1"); err != nil {
		t.Fatalf("DeleteByUserTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := s.Get("u1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after delete: want ErrNotFound, got %v", err)
	}
}

func TestSQLiteStore_GetSetErrorsOnClosedDB(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "dashboardlayout.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	_ = db.Close()
	if _, err := s.Get("u1"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Get on closed db: want non-NotFound error, got %v", err)
	}
	if err := s.Set("u1", `[]`); err == nil {
		t.Error("Set on closed db: want error, got nil")
	}
}

func TestNewSQLiteStoreErrorsOnClosedDB(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "dashboardlayout.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	_ = db.Close()
	if _, err := NewSQLiteStore(db); err == nil {
		t.Error("NewSQLiteStore on closed db: want error, got nil")
	}
}

func TestSQLiteStore_SchemaIsIdempotent(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "dashboardlayout.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := NewSQLiteStore(db); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if _, err := NewSQLiteStore(db); err != nil {
		t.Errorf("second init: %v", err)
	}
}
