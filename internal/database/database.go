// SPDX-License-Identifier: AGPL-3.0-or-later

// Package database opens the shared SQLite handle used by every domain
// package. Each domain (inventory, auth) owns its own table set and runs its
// own schema migration; this package only handles connection setup and
// pragmas so that ownership of the file isn't mixed up in any one domain.
package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// Open opens the SQLite database at dsn and applies the pragmas every domain
// package depends on (WAL, foreign keys, busy timeout). MaxOpenConns is fixed
// at 1 because SQLite serializes writes anyway and a single conn keeps
// :memory: tests sane.
func Open(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("database: open %q: %w", dsn, err)
	}
	db.SetMaxOpenConns(1)

	for _, p := range []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA busy_timeout=5000`,
	} {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("database: %s: %w", p, err)
		}
	}
	return db, nil
}
