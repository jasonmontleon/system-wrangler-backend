// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"fmt"
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
		return fmt.Sprintf("user-%d", n)
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
	if _, err := s.GetHashByID("u"); err == nil {
		t.Error("GetHashByID on closed DB: want error")
	}
	if _, err := s.UpdateProfile("u", "e", "dark"); err == nil {
		t.Error("UpdateProfile on closed DB: want error")
	}
	if err := s.UpdatePassword("u", "h"); err == nil {
		t.Error("UpdatePassword on closed DB: want error")
	}
	if _, _, err := s.LoadSecret("k"); err == nil {
		t.Error("LoadSecret on closed DB: want error")
	}
	if err := s.SaveSecret("k", []byte("v")); err == nil {
		t.Error("SaveSecret on closed DB: want error")
	}
	if _, err := s.CountEnabled(); err == nil {
		t.Error("CountEnabled on closed DB: want error")
	}
	if _, err := s.ListUsers(); err == nil {
		t.Error("ListUsers on closed DB: want error")
	}
	if _, err := s.SetDisabled("u", true, time.Now()); err == nil {
		t.Error("SetDisabled on closed DB: want error")
	}
}

func TestAuthStoreUpdateProfile(t *testing.T) {
	s := newTestAuthStore(t)
	u, err := s.Create("alice", "h")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	updated, err := s.UpdateProfile(u.ID, "alice@example.com", "light")
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if updated.Email != "alice@example.com" || updated.Theme != "light" {
		t.Errorf("got %+v", updated)
	}
	got, err := s.GetByID(u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Email != "alice@example.com" || got.Theme != "light" {
		t.Errorf("persisted = %+v", got)
	}
}

func TestAuthStoreUpdateProfileTrimsEmail(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	updated, err := s.UpdateProfile(u.ID, "  alice@example.com  ", "")
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if updated.Email != "alice@example.com" {
		t.Errorf("email = %q", updated.Email)
	}
}

func TestAuthStoreUpdateProfileInvalidTheme(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "h")
	if _, err := s.UpdateProfile(u.ID, "", "neon"); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestAuthStoreUpdateProfileMissingUser(t *testing.T) {
	s := newTestAuthStore(t)
	if _, err := s.UpdateProfile("ghost", "", "dark"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

func TestAuthStoreUpdatePassword(t *testing.T) {
	s := newTestAuthStore(t)
	u, _ := s.Create("alice", "old-hash")
	if err := s.UpdatePassword(u.ID, "new-hash"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	hash, err := s.GetHashByID(u.ID)
	if err != nil {
		t.Fatalf("GetHashByID: %v", err)
	}
	if hash != "new-hash" {
		t.Errorf("hash = %q, want %q", hash, "new-hash")
	}
}

func TestAuthStoreUpdatePasswordMissing(t *testing.T) {
	s := newTestAuthStore(t)
	if err := s.UpdatePassword("ghost", "h"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

func TestAuthStoreGetHashByIDMissing(t *testing.T) {
	s := newTestAuthStore(t)
	if _, err := s.GetHashByID("ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

// TestAuthStoreMigrateIdempotent re-opens the store on the same DB so the
// "column already present" branch in migrate runs.
func TestAuthStoreMigrateIdempotent(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "auth.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := NewSQLiteAuthStore(db); err != nil {
		t.Fatalf("first NewSQLiteAuthStore: %v", err)
	}
	if _, err := NewSQLiteAuthStore(db); err != nil {
		t.Fatalf("second NewSQLiteAuthStore: %v", err)
	}
}

// TestAuthStoreMigratesLegacySchema sets up a database with the original
// users table (no email/theme columns), then opens it through
// NewSQLiteAuthStore and exercises the new fields end-to-end.
func TestAuthStoreMigratesLegacySchema(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "auth.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
    ) STRICT`); err != nil {
		t.Fatalf("legacy schema: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		"u1", "alice", "h", int64(0),
	); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s, err := NewSQLiteAuthStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteAuthStore: %v", err)
	}
	got, err := s.GetByID("u1")
	if err != nil {
		t.Fatalf("GetByID after migrate: %v", err)
	}
	if got.Username != "alice" || got.Email != "" || got.Theme != "" {
		t.Errorf("migrated user = %+v", got)
	}
	if _, err := s.UpdateProfile("u1", "alice@x", "dark"); err != nil {
		t.Fatalf("UpdateProfile after migrate: %v", err)
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

func TestAuthStoreListUsersAndDisabled(t *testing.T) {
	s := newTestAuthStore(t)
	a, err := s.Create("alice", "h")
	if err != nil {
		t.Fatalf("Create alice: %v", err)
	}
	b, err := s.Create("bob", "h")
	if err != nil {
		t.Fatalf("Create bob: %v", err)
	}

	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("len = %d, want 2", len(users))
	}
	for _, u := range users {
		if u.Disabled || u.DisabledAt != nil {
			t.Errorf("fresh user %s: Disabled=%v DisabledAt=%v", u.Username, u.Disabled, u.DisabledAt)
		}
	}

	enabled, err := s.CountEnabled()
	if err != nil {
		t.Fatalf("CountEnabled: %v", err)
	}
	if enabled != 2 {
		t.Errorf("CountEnabled = %d, want 2", enabled)
	}

	when := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	updated, err := s.SetDisabled(b.ID, true, when)
	if err != nil {
		t.Fatalf("SetDisabled true: %v", err)
	}
	if !updated.Disabled || updated.DisabledAt == nil {
		t.Errorf("after disable: Disabled=%v DisabledAt=%v", updated.Disabled, updated.DisabledAt)
	}
	enabled, _ = s.CountEnabled()
	if enabled != 1 {
		t.Errorf("CountEnabled after disable = %d, want 1", enabled)
	}

	// Re-enable.
	reEnabled, err := s.SetDisabled(b.ID, false, when)
	if err != nil {
		t.Fatalf("SetDisabled false: %v", err)
	}
	if reEnabled.Disabled || reEnabled.DisabledAt != nil {
		t.Errorf("after re-enable: %+v", reEnabled)
	}

	// Missing user.
	if _, err := s.SetDisabled("ghost", true, when); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("SetDisabled ghost err = %v, want ErrUserNotFound", err)
	}
	_ = a
}
