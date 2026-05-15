// SPDX-License-Identifier: Apache-2.0

// Package backup produces SQLite snapshots of the System Wrangler
// database via `VACUUM INTO`. Design and discipline:
// research/db-backup.md.
//
// Mechanism: a single SQL statement copies every page into a brand-new,
// defragmented `.db` file at a snapshot moment. The output is a plain
// SQLite database with no WAL or SHM sidecar, so operators can copy it
// anywhere and restore by overwriting `system-wrangler.db` while the
// container is stopped. Restore is intentionally not an API — live-
// process file replacement is too fragile to support officially.
package backup

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// ErrInFlight is returned by Create when another backup is already
// running. The endpoint maps this to HTTP 409 so a second concurrent
// VACUUM INTO does not pin the disk for no benefit.
var ErrInFlight = errors.New("backup: another backup is already in progress")

// Service produces snapshots of a *sql.DB. One per process. The
// inFlight gate serializes Create across goroutines so concurrent
// callers don't compete for the same disk pages.
type Service struct {
	// DB is the live database handle. Required.
	DB *sql.DB
	// TempDir is the directory where the intermediate snapshot lands.
	// Empty means os.TempDir(). Tests point this at t.TempDir() so the
	// file is cleaned up automatically.
	TempDir string
	// NewID returns the random component of the snapshot filename. The
	// returned string MUST only contain characters safe inside a SQLite
	// string literal (alphanumeric is the simple bar). nil falls back
	// to 16 hex bytes from crypto/rand.
	NewID func() (string, error)

	inFlight atomic.Bool
}

// Snapshot is the file produced by Create. The caller is responsible
// for streaming Path and then calling Close to remove the temp file
// and release the in-flight slot.
type Snapshot struct {
	// Path is the on-disk location of the snapshot. Plain SQLite .db
	// file; no WAL or SHM sidecar.
	Path string
	// Size is the snapshot's size in bytes, recorded once at creation.
	Size int64

	release func()
}

// Close removes the temp file and releases the in-flight slot so the
// next Create can proceed. Safe to call more than once; subsequent
// calls are no-ops.
func (s *Snapshot) Close() error {
	if s == nil || s.release == nil {
		return nil
	}
	s.release()
	s.release = nil
	return nil
}

// Create runs `VACUUM INTO` against a fresh temp file under TempDir and
// returns the resulting Snapshot. Returns ErrInFlight if another
// backup is already in progress. The caller must call Snapshot.Close
// once the response has been streamed (or on error).
func (s *Service) Create(ctx context.Context) (*Snapshot, error) {
	if s.DB == nil {
		return nil, errors.New("backup: DB is nil")
	}
	if !s.inFlight.CompareAndSwap(false, true) {
		return nil, ErrInFlight
	}
	releaseSlot := func() { s.inFlight.Store(false) }

	id, err := s.newID()
	if err != nil {
		releaseSlot()
		return nil, fmt.Errorf("backup: new id: %w", err)
	}
	dir := s.TempDir
	if dir == "" {
		dir = os.TempDir()
	}
	path := filepath.Join(dir, "sw-backup-"+id+".db")

	if err := vacuumInto(ctx, s.DB, path); err != nil {
		_ = os.Remove(path)
		releaseSlot()
		return nil, fmt.Errorf("backup: vacuum into: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		_ = os.Remove(path)
		releaseSlot()
		return nil, fmt.Errorf("backup: stat: %w", err)
	}
	return &Snapshot{
		Path: path,
		Size: info.Size(),
		release: func() {
			_ = os.Remove(path)
			releaseSlot()
		},
	}, nil
}

func (s *Service) newID() (string, error) {
	if s.NewID != nil {
		return s.NewID()
	}
	return defaultNewID()
}

// defaultNewID returns 16 hex bytes from crypto/rand. Hex is the
// simplest character set that's both URL-safe and SQL-literal-safe.
func defaultNewID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// vacuumInto runs `VACUUM INTO '<path>'`. SQLite parses the destination
// as a literal string, not a bound parameter, so we embed it in the
// SQL string and escape single quotes per SQLite literal rules
// (doubled). The path itself is server-generated (TempDir +
// "sw-backup-" + hex), so the escape is belt-and-braces against an
// operator-supplied TempDir that happens to contain a quote.
func vacuumInto(ctx context.Context, db *sql.DB, path string) error {
	escaped := strings.ReplaceAll(path, "'", "''")
	// Path is server-controlled (caller-supplied TempDir + hex random),
	// and single quotes are escaped. gosec G202 false positive on
	// concatenation into the SQL string.
	stmt := "VACUUM INTO '" + escaped + "'" //nolint:gosec
	_, err := db.ExecContext(ctx, stmt)
	return err
}
