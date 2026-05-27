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
