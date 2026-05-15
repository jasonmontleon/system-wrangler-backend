// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"system-wrangler-backend/internal/database"
)

func openTestDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "src.db")
	db, err := database.Open("file:" + dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE marker (k TEXT PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO marker(k, v) VALUES ('hello', 'world')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return dbPath
}

func TestService_Create_ProducesValidSQLiteSnapshot(t *testing.T) {
	srcPath := openTestDB(t)
	srcDB, err := database.Open("file:" + srcPath)
	if err != nil {
		t.Fatalf("reopen src: %v", err)
	}
	defer func() { _ = srcDB.Close() }()

	s := &Service{DB: srcDB, TempDir: t.TempDir()}
	snap, err := s.Create(context.Background())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = snap.Close() }()

	if snap.Path == "" {
		t.Fatal("snap.Path is empty")
	}
	if snap.Size <= 0 {
		t.Fatalf("snap.Size = %d, want > 0", snap.Size)
	}
	if _, err := os.Stat(snap.Path); err != nil {
		t.Fatalf("snap file missing: %v", err)
	}

	// Open the snapshot independently and confirm the marker row made it.
	snapDB, err := database.Open("file:" + snap.Path)
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer func() { _ = snapDB.Close() }()
	var v string
	if err := snapDB.QueryRow(`SELECT v FROM marker WHERE k = 'hello'`).Scan(&v); err != nil {
		t.Fatalf("read marker from snapshot: %v", err)
	}
	if v != "world" {
		t.Errorf("marker value = %q, want %q", v, "world")
	}
}

func TestSnapshot_Close_RemovesFileAndReleasesSlot(t *testing.T) {
	srcPath := openTestDB(t)
	srcDB, _ := database.Open("file:" + srcPath)
	defer func() { _ = srcDB.Close() }()

	s := &Service{DB: srcDB, TempDir: t.TempDir()}
	snap, err := s.Create(context.Background())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	path := snap.Path
	if err := snap.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("snap file not removed: stat err = %v", err)
	}
	// Slot should be released — a second Create must succeed.
	snap2, err := s.Create(context.Background())
	if err != nil {
		t.Fatalf("second Create after Close: %v", err)
	}
	_ = snap2.Close()

	// Double Close is a no-op.
	if err := snap.Close(); err != nil {
		t.Errorf("second Close returned %v, want nil", err)
	}
}

func TestService_Create_ConcurrentReturnsInFlight(t *testing.T) {
	srcPath := openTestDB(t)
	srcDB, _ := database.Open("file:" + srcPath)
	defer func() { _ = srcDB.Close() }()

	s := &Service{DB: srcDB, TempDir: t.TempDir()}
	snap, err := s.Create(context.Background())
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	defer func() { _ = snap.Close() }()

	if _, err := s.Create(context.Background()); !errors.Is(err, ErrInFlight) {
		t.Errorf("second Create err = %v, want ErrInFlight", err)
	}
}

func TestService_Create_ParallelCallsSerialize(t *testing.T) {
	srcPath := openTestDB(t)
	srcDB, _ := database.Open("file:" + srcPath)
	defer func() { _ = srcDB.Close() }()

	s := &Service{DB: srcDB, TempDir: t.TempDir()}

	const goroutines = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		success  int
		inFlight int
		other    []error
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			snap, err := s.Create(context.Background())
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				success++
				_ = snap.Close()
			case errors.Is(err, ErrInFlight):
				inFlight++
			default:
				other = append(other, err)
			}
		}()
	}
	wg.Wait()
	if len(other) > 0 {
		t.Fatalf("unexpected errors: %v", other)
	}
	if success == 0 {
		t.Fatal("no goroutine succeeded")
	}
	if success+inFlight != goroutines {
		t.Errorf("success=%d inFlight=%d sum=%d want=%d", success, inFlight, success+inFlight, goroutines)
	}
}

func TestService_Create_NilDB(t *testing.T) {
	s := &Service{}
	if _, err := s.Create(context.Background()); err == nil {
		t.Fatal("Create with nil DB: want error, got nil")
	}
}

func TestService_Create_NewIDError(t *testing.T) {
	srcPath := openTestDB(t)
	srcDB, _ := database.Open("file:" + srcPath)
	defer func() { _ = srcDB.Close() }()

	sentinel := errors.New("boom")
	s := &Service{
		DB:      srcDB,
		TempDir: t.TempDir(),
		NewID:   func() (string, error) { return "", sentinel },
	}
	_, err := s.Create(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("Create err = %v, want sentinel", err)
	}
	// Slot must be released so a subsequent good Create works.
	s.NewID = func() (string, error) { return "deadbeef", nil }
	snap, err := s.Create(context.Background())
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	_ = snap.Close()
}

func TestService_Create_VacuumFailsReleasesSlot(t *testing.T) {
	srcPath := openTestDB(t)
	srcDB, _ := database.Open("file:" + srcPath)
	defer func() { _ = srcDB.Close() }()

	// Point TempDir at a nonexistent directory so VACUUM INTO fails on
	// open. The slot must still release.
	s := &Service{DB: srcDB, TempDir: filepath.Join(t.TempDir(), "missing")}
	if _, err := s.Create(context.Background()); err == nil {
		t.Fatal("Create with bad TempDir: want error, got nil")
	}
	s.TempDir = t.TempDir()
	snap, err := s.Create(context.Background())
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	_ = snap.Close()
}

func TestVacuumInto_EscapesSingleQuotes(t *testing.T) {
	srcPath := openTestDB(t)
	srcDB, _ := database.Open("file:" + srcPath)
	defer func() { _ = srcDB.Close() }()

	dir := t.TempDir()
	// Filename with a single quote — SQLite literal escape doubles it.
	path := filepath.Join(dir, "weird's-name.db")
	if err := vacuumInto(context.Background(), srcDB, path); err != nil {
		t.Fatalf("vacuumInto: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("output missing: %v", err)
	}
	// Confirm contents are a real SQLite DB (header magic).
	b, err := os.ReadFile(path) //nolint:gosec // path is t.TempDir() under test control
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.HasPrefix(string(b), "SQLite format 3") {
		t.Errorf("output is not a SQLite file (header=%q)", string(b[:16]))
	}
}

func TestDefaultNewID_HexAndNonEmpty(t *testing.T) {
	id, err := defaultNewID()
	if err != nil {
		t.Fatalf("defaultNewID: %v", err)
	}
	if len(id) != 32 {
		t.Errorf("len = %d, want 32 hex chars", len(id))
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("non-hex char %q in id %q", c, id)
		}
	}
}
