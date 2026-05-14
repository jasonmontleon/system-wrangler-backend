// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/auth"
	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/groups"
	"system-wrangler-backend/internal/systems"
)

// fixture spins up a temp SQLite db with the auth + groups + systems
// schemas already migrated, since the rbac store's FK references
// depend on users(id) and system_groups(id) existing, and groups.Delete
// touches the hosts table that the systems package owns. The rbac
// store is NOT constructed here — every test in this file wants to
// control the backfill timing relative to the users that exist in
// the DB.
type fixture struct {
	db     *sql.DB
	auth   *auth.SQLiteAuthStore
	groups *groups.SQLiteStore
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "rbac.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := auth.NewSQLiteAuthStore(db)
	if err != nil {
		t.Fatalf("auth.NewSQLiteAuthStore: %v", err)
	}
	if _, err := systems.NewSQLiteStore(db); err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	g, err := groups.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("groups.NewSQLiteStore: %v", err)
	}
	return fixture{db: db, auth: a, groups: g}
}

func mustUser(t *testing.T, a *auth.SQLiteAuthStore, name string) string {
	t.Helper()
	u, err := a.Create(name, "hash")
	if err != nil {
		t.Fatalf("auth.Create %s: %v", name, err)
	}
	return u.ID
}

func TestBackfillExistingUsersGetGlobalAdmin(t *testing.T) {
	f := newFixture(t)
	uid := mustUser(t, f.auth, "alice")
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	rows, err := store.Resolve(uid)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(rows) != 1 || rows[0].Role != RoleAdmin || rows[0].GroupID != nil {
		t.Errorf("after backfill, Resolve = %+v, want one global admin row", rows)
	}
}

func TestBackfillRunsOnceEvenAfterRevoke(t *testing.T) {
	f := newFixture(t)
	uid := mustUser(t, f.auth, "alice")
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := store.Revoke(Assignment{UserID: uid, Role: RoleAdmin}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := NewSQLiteStore(f.db); err != nil {
		t.Fatalf("NewSQLiteStore second time: %v", err)
	}
	rows, err := store.Resolve(uid)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("after Revoke + restart, Resolve = %+v, want empty (no re-backfill)", rows)
	}
}

func TestBackfillSkippedOnEmptyUsersTable(t *testing.T) {
	f := newFixture(t)
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	uid := mustUser(t, f.auth, "alice")
	rows, err := store.Resolve(uid)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("user created after first boot must start with zero rows, got %+v", rows)
	}
}

func TestGrantAndResolve(t *testing.T) {
	f := newFixture(t)
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	uid := mustUser(t, f.auth, "alice")
	g, err := f.groups.Create(groups.GroupInput{Name: "prod"})
	if err != nil {
		t.Fatalf("groups.Create: %v", err)
	}
	if err := store.Grant(Assignment{UserID: uid, GroupID: &g.ID, Role: RoleOperator}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	rows, err := store.Resolve(uid)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(rows) != 1 || rows[0].Role != RoleOperator || rows[0].GroupID == nil || *rows[0].GroupID != g.ID {
		t.Errorf("Resolve = %+v, want one operator row on %s", rows, g.ID)
	}
}

// TestGrantGlobalDuplicateRejected pins the COALESCE expression index
// behavior. Without it, two NULL group_id rows for the same user+role
// would both succeed because SQLite treats NULLs as distinct in UNIQUE
// constraints. The expression index folds NULL to ”.
func TestGrantGlobalDuplicateRejected(t *testing.T) {
	f := newFixture(t)
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	uid := mustUser(t, f.auth, "alice")
	if err := store.Grant(Assignment{UserID: uid, Role: RoleOperator}); err != nil {
		t.Fatalf("Grant 1: %v", err)
	}
	if err := store.Grant(Assignment{UserID: uid, Role: RoleOperator}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("Grant 2 err = %v, want ErrDuplicate", err)
	}
}

func TestGrantDuplicate(t *testing.T) {
	f := newFixture(t)
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	uid := mustUser(t, f.auth, "alice")
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	a := Assignment{UserID: uid, GroupID: &g.ID, Role: RoleAuditor}
	if err := store.Grant(a); err != nil {
		t.Fatalf("Grant 1: %v", err)
	}
	if err := store.Grant(a); !errors.Is(err, ErrDuplicate) {
		t.Errorf("Grant 2 err = %v, want ErrDuplicate", err)
	}
}

func TestGrantRejectsUnknownRole(t *testing.T) {
	f := newFixture(t)
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	uid := mustUser(t, f.auth, "alice")
	err = store.Grant(Assignment{UserID: uid, Role: Role("bogus")})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestRevoke(t *testing.T) {
	f := newFixture(t)
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	uid := mustUser(t, f.auth, "alice")
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	a := Assignment{UserID: uid, GroupID: &g.ID, Role: RoleOperator}
	if err := store.Grant(a); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if err := store.Revoke(a); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := store.Revoke(a); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Revoke err = %v, want ErrNotFound", err)
	}
}

func TestRevokeGlobalVsGroupRowsAreDistinct(t *testing.T) {
	f := newFixture(t)
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	uid := mustUser(t, f.auth, "alice")
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	if err := store.Grant(Assignment{UserID: uid, Role: RoleAdmin}); err != nil {
		t.Fatalf("Grant global: %v", err)
	}
	if err := store.Grant(Assignment{UserID: uid, GroupID: &g.ID, Role: RoleAdmin}); err != nil {
		t.Fatalf("Grant group: %v", err)
	}
	if err := store.Revoke(Assignment{UserID: uid, Role: RoleAdmin}); err != nil {
		t.Fatalf("Revoke global: %v", err)
	}
	rows, err := store.Resolve(uid)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(rows) != 1 || rows[0].GroupID == nil {
		t.Errorf("after revoking global, expected only group row to remain, got %+v", rows)
	}
}

func TestListByGroup(t *testing.T) {
	f := newFixture(t)
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	uid1 := mustUser(t, f.auth, "alice")
	uid2 := mustUser(t, f.auth, "bob")
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	other, _ := f.groups.Create(groups.GroupInput{Name: "staging"})
	_ = store.Grant(Assignment{UserID: uid1, GroupID: &g.ID, Role: RoleAdmin})
	_ = store.Grant(Assignment{UserID: uid2, GroupID: &g.ID, Role: RoleOperator})
	_ = store.Grant(Assignment{UserID: uid1, GroupID: &other.ID, Role: RoleAuditor})
	_ = store.Grant(Assignment{UserID: uid1, Role: RoleAdmin}) // global, must not appear

	rows, err := store.ListByGroup(g.ID)
	if err != nil {
		t.Fatalf("ListByGroup: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("ListByGroup len = %d, want 2; rows = %+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.GroupID == nil || *r.GroupID != g.ID {
			t.Errorf("row has wrong group: %+v", r)
		}
	}
}

func TestListAllIncludesGlobalRows(t *testing.T) {
	f := newFixture(t)
	uid := mustUser(t, f.auth, "alice")
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	rows, err := store.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.UserID == uid && r.GroupID == nil && r.Role == RoleAdmin {
			found = true
		}
	}
	if !found {
		t.Errorf("ListAll did not include backfilled global admin: %+v", rows)
	}
}

func TestCascadeOnUserDelete(t *testing.T) {
	f := newFixture(t)
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	uid := mustUser(t, f.auth, "alice")
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	_ = store.Grant(Assignment{UserID: uid, GroupID: &g.ID, Role: RoleAdmin})
	if err := f.auth.Delete(uid); err != nil {
		t.Fatalf("auth.Delete: %v", err)
	}
	rows, _ := store.Resolve(uid)
	if len(rows) != 0 {
		t.Errorf("after user delete, rows = %+v, want empty (cascade)", rows)
	}
}

func TestIsUniqueViolationOnNil(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Error("isUniqueViolation(nil) = true, want false")
	}
}

// TestBackfillSurfacesDBErrors drops the users table after the rbac
// schema is in place but before the first backfill, exercising the
// "tx.Query users" error path in backfillOnce.
func TestBackfillSurfacesDBErrors(t *testing.T) {
	f := newFixture(t)
	if _, err := f.db.Exec(schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if _, err := f.db.Exec(`DROP TABLE users`); err != nil {
		t.Fatalf("drop users: %v", err)
	}
	if _, err := NewSQLiteStore(f.db); err == nil {
		t.Error("NewSQLiteStore = nil err, want error from missing users table")
	}
}

// TestStoreErrorsAfterDBClose closes the underlying *sql.DB and asserts
// every read/write surface returns an error rather than panicking or
// returning a nil result. Exercises the "DB is unhealthy" branches.
func TestStoreErrorsAfterDBClose(t *testing.T) {
	f := newFixture(t)
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}
	gid := "g"
	if _, err := store.Resolve("u"); err == nil {
		t.Error("Resolve after close = nil")
	}
	if err := store.Grant(Assignment{UserID: "u", Role: RoleAdmin}); err == nil {
		t.Error("Grant after close = nil")
	}
	if err := store.Grant(Assignment{UserID: "u", GroupID: &gid, Role: RoleAdmin}); err == nil {
		t.Error("Grant (with group) after close = nil")
	}
	if err := store.Revoke(Assignment{UserID: "u", Role: RoleAdmin}); err == nil {
		t.Error("Revoke after close = nil")
	}
	if err := store.Revoke(Assignment{UserID: "u", GroupID: &gid, Role: RoleAdmin}); err == nil {
		t.Error("Revoke (with group) after close = nil")
	}
	if _, err := store.ListByGroup("g"); err == nil {
		t.Error("ListByGroup after close = nil")
	}
	if _, err := store.ListAll(); err == nil {
		t.Error("ListAll after close = nil")
	}
	if _, err := NewSQLiteStore(f.db); err == nil {
		t.Error("NewSQLiteStore on closed db = nil")
	}
}

func TestCascadeOnGroupDelete(t *testing.T) {
	f := newFixture(t)
	store, err := NewSQLiteStore(f.db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	uid := mustUser(t, f.auth, "alice")
	g, _ := f.groups.Create(groups.GroupInput{Name: "prod"})
	_ = store.Grant(Assignment{UserID: uid, GroupID: &g.ID, Role: RoleAdmin})
	if err := f.groups.Delete(g.ID); err != nil {
		t.Fatalf("groups.Delete: %v", err)
	}
	rows, _ := store.Resolve(uid)
	// Global backfill row should still be present; per-group row should be gone.
	for _, r := range rows {
		if r.GroupID != nil && *r.GroupID == g.ID {
			t.Errorf("after group delete, found surviving group row %+v", r)
		}
	}
}
