// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"system-wrangler-backend/internal/database"
)

func newTestAuthStore(t *testing.T) *SQLiteAuthStore {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "auth.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := NewSQLiteAuthStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteAuthStore: %v", err)
	}
	var n int
	s.NewID = func() string {
		n++
		return "user-" + string(rune('0'+n))
	}
	s.Now = func() time.Time {
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return s
}

func TestAuthStoreCountEmpty(t *testing.T) {
	s := newTestAuthStore(t)
	n, err := s.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 0 {
		t.Errorf("Count = %d, want 0", n)
	}
}

func TestAuthStoreCreateAndGetters(t *testing.T) {
	s := newTestAuthStore(t)
	u, err := s.Create("alice", "hashvalue")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.ID == "" || u.Username != "alice" {
		t.Errorf("got %+v", u)
	}
	if u.CreatedAt.Location() != time.UTC {
		t.Error("CreatedAt should be UTC")
	}

	n, _ := s.Count()
	if n != 1 {
		t.Errorf("Count = %d, want 1", n)
	}

	got, hash, err := s.GetByUsername("alice")
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if got.ID != u.ID || hash != "hashvalue" {
		t.Errorf("got user %+v hash %q", got, hash)
	}

	got2, err := s.GetByID(u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got2.Username != "alice" {
		t.Errorf("GetByID returned %+v", got2)
	}
}

func TestAuthStoreCreateTrimsAndRejectsEmpty(t *testing.T) {
	s := newTestAuthStore(t)
	u, err := s.Create("  bob  ", "h")
	if err != nil {
		t.Fatalf("Create with whitespace: %v", err)
	}
	if u.Username != "bob" {
		t.Errorf("username = %q, want %q", u.Username, "bob")
	}
	if _, err := s.Create("   ", "h"); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty create err = %v, want ErrInvalid", err)
	}
}

func TestAuthStoreCreateDuplicate(t *testing.T) {
	s := newTestAuthStore(t)
	if _, err := s.Create("alice", "h1"); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := s.Create("alice", "h2")
	if !errors.Is(err, ErrUserExists) {
		t.Errorf("err = %v, want ErrUserExists", err)
	}
}

func TestAuthStoreGetMissing(t *testing.T) {
	s := newTestAuthStore(t)
	if _, _, err := s.GetByUsername("nope"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("GetByUsername err = %v, want ErrUserNotFound", err)
	}
	if _, err := s.GetByID("nope"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("GetByID err = %v, want ErrUserNotFound", err)
	}
}

// TestAuthStoreErrorsOnClosedDB drives the error path on every method by
// closing the DB out from under the store.
func TestAuthStoreErrorsOnClosedDB(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "auth.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s, err := NewSQLiteAuthStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteAuthStore: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := s.Count(); err == nil {
		t.Error("Count on closed DB: want error")
	}
	if _, err := s.Create("u", "h"); err == nil {
		t.Error("Create on closed DB: want error")
	}
	if _, _, err := s.GetByUsername("u"); err == nil {
		t.Error("GetByUsername on closed DB: want error")
	}
	if _, err := s.GetByID("u"); err == nil {
		t.Error("GetByID on closed DB: want error")
	}
	if _, _, err := s.LoadSecret("k"); err == nil {
		t.Error("LoadSecret on closed DB: want error")
	}
	if err := s.SaveSecret("k", []byte("v")); err == nil {
		t.Error("SaveSecret on closed DB: want error")
	}
}

// TestNewSQLiteAuthStoreSchemaError verifies the schema-exec error path.
func TestNewSQLiteAuthStoreSchemaError(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "auth.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := NewSQLiteAuthStore(db); err == nil {
		t.Error("NewSQLiteAuthStore on closed DB: want error")
	}
}

func TestAuthStoreSecretRoundTrip(t *testing.T) {
	s := newTestAuthStore(t)
	if _, ok, err := s.LoadSecret("k"); err != nil || ok {
		t.Errorf("missing key: ok=%v err=%v", ok, err)
	}
	want := []byte{1, 2, 3, 4}
	if err := s.SaveSecret("k", want); err != nil {
		t.Fatalf("SaveSecret: %v", err)
	}
	got, ok, err := s.LoadSecret("k")
	if err != nil || !ok {
		t.Fatalf("Load after save: ok=%v err=%v", ok, err)
	}
	if string(got) != string(want) {
		t.Errorf("got %v, want %v", got, want)
	}

	// Overwrite — UPSERT semantics.
	if err := s.SaveSecret("k", []byte{9}); err != nil {
		t.Fatalf("re-save: %v", err)
	}
	got, _, _ = s.LoadSecret("k")
	if string(got) != string([]byte{9}) {
		t.Errorf("after upsert got %v, want [9]", got)
	}
}
