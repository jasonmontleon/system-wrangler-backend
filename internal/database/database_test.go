// SPDX-License-Identifier: AGPL-3.0-or-later

package database

import (
	"path/filepath"
	"testing"
)

func TestOpenAppliesPragmas(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "test.db")
	db, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	tests := []struct {
		pragma string
		want   string
	}{
		{`PRAGMA journal_mode`, "wal"},
		{`PRAGMA foreign_keys`, "1"},
	}
	for _, tt := range tests {
		t.Run(tt.pragma, func(t *testing.T) {
			var got string
			if err := db.QueryRow(tt.pragma).Scan(&got); err != nil {
				t.Fatalf("query %s: %v", tt.pragma, err)
			}
			if got != tt.want {
				t.Errorf("%s = %q, want %q", tt.pragma, got, tt.want)
			}
		})
	}
}

func TestOpenBadPath(t *testing.T) {
	_, err := Open("file:/nonexistent-dir-xyzzy/never.db")
	if err == nil {
		t.Fatal("Open on bad path: want error, got nil")
	}
}
