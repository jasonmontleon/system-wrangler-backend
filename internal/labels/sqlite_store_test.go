// SPDX-License-Identifier: Apache-2.0

package labels_test

import (
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/labels"
	"system-wrangler-backend/internal/systems"
)

func TestSQLiteStoreIdempotent(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "labels-idem.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := labels.NewSQLiteStore(db); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if _, err := labels.NewSQLiteStore(db); err != nil {
		t.Fatalf("second init: %v", err)
	}
}

// TestSQLiteCascadeOnSystemDelete verifies the ON DELETE CASCADE
// referential action that the schema relies on for cleanup. If a system
// goes away the label rows must vanish in the same statement.
func TestSQLiteCascadeOnSystemDelete(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "labels-cascade.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems init: %v", err)
	}
	store, err := labels.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("labels init: %v", err)
	}
	sys, err := sysStore.Create(systems.SystemInput{Name: "h1", Hostname: "h1.example"})
	if err != nil {
		t.Fatalf("systems.Create: %v", err)
	}
	v := "prod"
	if _, err := store.Set(sys.ID, "env", &v, false); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := sysStore.Delete(sys.ID); err != nil {
		t.Fatalf("systems.Delete: %v", err)
	}
	labels, err := store.ForSystem(sys.ID)
	if err != nil {
		t.Fatalf("for system after delete: %v", err)
	}
	if len(labels) != 0 {
		t.Errorf("after system delete got labels = %+v, want none", labels)
	}
}

func TestLabelStoresClosedDBSurfacesErrors(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "labels-closed.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := systems.NewSQLiteStore(db); err != nil {
		t.Fatalf("systems: %v", err)
	}
	ls, err := labels.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("labels: %v", err)
	}
	ss, err := labels.NewSQLiteStyleStore(db)
	if err != nil {
		t.Fatalf("styles: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	val := "v"
	type call struct {
		name string
		fn   func() error
	}
	calls := []call{
		{"Set", func() error { _, err := ls.Set("s", "k", &val, false); return err }},
		{"Delete", func() error { return ls.Delete("s", "k") }},
		{"ForSystem", func() error { _, err := ls.ForSystem("s"); return err }},
		{"ForSystems", func() error { _, err := ls.ForSystems([]string{"s"}); return err }},
		{"Summary", func() error { _, err := ls.Summary(); return err }},
		{"Styles.All", func() error { _, err := ss.All(); return err }},
		{"Styles.Set", func() error { return ss.Set("k", "blue") }},
		{"Styles.Delete", func() error { return ss.Delete("k") }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			if err := c.fn(); err == nil {
				t.Errorf("%s on closed DB returned nil error", c.name)
			}
		})
	}
}
