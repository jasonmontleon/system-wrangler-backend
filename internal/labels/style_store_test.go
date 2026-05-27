// SPDX-License-Identifier: Apache-2.0

package labels_test

import (
	"errors"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/labels"
)

func TestSQLiteStyleStore(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "label-styles.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s, err := labels.NewSQLiteStyleStore(db)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	// Idempotent migration.
	if _, err := labels.NewSQLiteStyleStore(db); err != nil {
		t.Fatalf("re-init: %v", err)
	}

	if err := s.Set("env", "blue"); err != nil {
		t.Fatalf("set: %v", err)
	}
	all, err := s.All()
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if all["env"] != "blue" {
		t.Errorf("all = %+v, want env=blue", all)
	}

	// Upsert via Set on an existing key replaces the color.
	if err := s.Set("env", "green"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	all, _ = s.All()
	if all["env"] != "green" {
		t.Errorf("after upsert all = %+v, want env=green", all)
	}

	if err := s.Delete("env"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	all, _ = s.All()
	if _, ok := all["env"]; ok {
		t.Errorf("after delete all = %+v, want env absent", all)
	}
	if err := s.Delete("env"); !errors.Is(err, labels.ErrNotFound) {
		t.Errorf("re-delete: err = %v, want ErrNotFound", err)
	}
}

func TestValidateColor(t *testing.T) {
	for _, c := range labels.AllowedColors {
		if err := labels.ValidateColor(c); err != nil {
			t.Errorf("ValidateColor(%q) = %v, want nil", c, err)
		}
	}
	for _, c := range []string{"", "chartreuse", "BLUE"} {
		if err := labels.ValidateColor(c); !errors.Is(err, labels.ErrInvalidColor) {
			t.Errorf("ValidateColor(%q) err = %v, want ErrInvalidColor", c, err)
		}
	}
}
