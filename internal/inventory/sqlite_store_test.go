// SPDX-License-Identifier: AGPL-3.0-or-later

package inventory

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestSQLiteStore opens an SQLiteStore against a per-test file with the
// same deterministic NewID/Now overrides as newTestStore, so the assertions
// in this file mirror the MemStore tests.
func newTestSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "test.db")
	s, err := OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	var counter atomic.Int64
	s.NewID = func() string {
		return fmt.Sprintf("id-%d", counter.Add(1))
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var tick atomic.Int64
	s.Now = func() time.Time {
		return base.Add(time.Duration(tick.Add(1)) * time.Second)
	}
	return s
}

func TestSQLiteOpenInvalidDSN(t *testing.T) {
	// A path under a nonexistent directory cannot be created; SQLite returns
	// an error during the first PRAGMA exec.
	_, err := OpenSQLite("file:/nonexistent-dir-xyzzy/never.db")
	if err == nil {
		t.Fatal("OpenSQLite on bad path: want error, got nil")
	}
}

func TestSQLiteStoreCreateAndGet(t *testing.T) {
	s := newTestSQLiteStore(t)
	h, err := s.Create(HostInput{Name: "  host1 ", Hostname: " 10.0.0.1 "})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if h.ID != "id-1" {
		t.Errorf("ID = %q, want id-1", h.ID)
	}
	if h.Name != "host1" || h.Hostname != "10.0.0.1" {
		t.Errorf("trim failed: %+v", h)
	}
	if h.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
	if h.CreatedAt.Location() != time.UTC {
		t.Error("CreatedAt should be UTC")
	}
	if h.Status != StatusUnprobed {
		t.Errorf("Status = %q, want %q", h.Status, StatusUnprobed)
	}
	if h.LastSeen != nil {
		t.Errorf("LastSeen = %v, want nil", h.LastSeen)
	}

	got, err := s.Get(h.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Compare fields rather than struct equality: time.Time round-tripping
	// through SQLite should be exact (UnixNano), but be explicit.
	if got.ID != h.ID || got.Name != h.Name || got.Hostname != h.Hostname {
		t.Errorf("Get returned %+v, want %+v", got, h)
	}
	if !got.CreatedAt.Equal(h.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, h.CreatedAt)
	}
	if got.Status != h.Status {
		t.Errorf("Status = %q, want %q", got.Status, h.Status)
	}
}

func TestSQLiteStoreCreateInvalid(t *testing.T) {
	s := newTestSQLiteStore(t)
	_, err := s.Create(HostInput{Name: "", Hostname: "1.2.3.4"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	hosts, _ := s.List()
	if len(hosts) != 0 {
		t.Errorf("invalid create should not persist; got %d hosts", len(hosts))
	}
}

func TestSQLiteStoreGetMissing(t *testing.T) {
	s := newTestSQLiteStore(t)
	if _, err := s.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestSQLiteStoreListOrdered(t *testing.T) {
	s := newTestSQLiteStore(t)
	for i := 0; i < 3; i++ {
		if _, err := s.Create(HostInput{Name: "h" + strconv.Itoa(i), Hostname: "1.1.1.1"}); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	hosts, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("len = %d, want 3", len(hosts))
	}
	for i := 1; i < len(hosts); i++ {
		if hosts[i].CreatedAt.Before(hosts[i-1].CreatedAt) {
			t.Errorf("hosts not ordered by CreatedAt: %+v", hosts)
		}
	}
}

func TestSQLiteStoreListEmpty(t *testing.T) {
	s := newTestSQLiteStore(t)
	hosts, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("len = %d, want 0", len(hosts))
	}
	// Non-nil empty slice keeps JSON marshaling as `[]` not `null`.
	if hosts == nil {
		t.Error("List on empty store returned nil; want non-nil empty slice")
	}
}

func TestSQLiteStoreDelete(t *testing.T) {
	s := newTestSQLiteStore(t)
	h, _ := s.Create(HostInput{Name: "h", Hostname: "1.1.1.1"})
	if err := s.Delete(h.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(h.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete Get err = %v, want ErrNotFound", err)
	}
	if err := s.Delete(h.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete err = %v, want ErrNotFound", err)
	}
}

func TestSQLiteStoreUpdateProbe(t *testing.T) {
	s := newTestSQLiteStore(t)
	h, _ := s.Create(HostInput{Name: "h", Hostname: "1.1.1.1"})
	probeAt := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	if err := s.UpdateProbe(h.ID, true, probeAt); err != nil {
		t.Fatalf("UpdateProbe ok: %v", err)
	}
	got, _ := s.Get(h.ID)
	if got.Status != StatusReachable {
		t.Errorf("Status = %q, want reachable", got.Status)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(probeAt) {
		t.Errorf("LastSeen = %v, want %v", got.LastSeen, probeAt)
	}

	// A failed probe sets Unreachable but preserves LastSeen.
	failAt := probeAt.Add(time.Minute)
	if err := s.UpdateProbe(h.ID, false, failAt); err != nil {
		t.Fatalf("UpdateProbe fail: %v", err)
	}
	got, _ = s.Get(h.ID)
	if got.Status != StatusUnreachable {
		t.Errorf("Status = %q, want unreachable", got.Status)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(probeAt) {
		t.Errorf("LastSeen = %v, want preserved %v", got.LastSeen, probeAt)
	}
}

func TestSQLiteStoreUpdateProbeMissing(t *testing.T) {
	s := newTestSQLiteStore(t)
	if err := s.UpdateProbe("nope", true, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// TestSQLiteStorePersistence verifies that data written by one *SQLiteStore
// is visible when the same DB file is reopened — guarding against any future
// change that accidentally moves state into process-local memory.
func TestSQLiteStorePersistence(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "persist.db")

	s1, err := OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("OpenSQLite #1: %v", err)
	}
	h, err := s1.Create(HostInput{Name: "persisted", Hostname: "10.0.0.99"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := OpenSQLite(dsn)
	if err != nil {
		t.Fatalf("OpenSQLite #2: %v", err)
	}
	defer s2.Close()

	got, err := s2.Get(h.ID)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.Name != "persisted" || got.Hostname != "10.0.0.99" {
		t.Errorf("after reopen got %+v", got)
	}
	if !got.CreatedAt.Equal(h.CreatedAt) {
		t.Errorf("CreatedAt drifted: %v vs %v", got.CreatedAt, h.CreatedAt)
	}
}

// TestSQLiteStoreConcurrent exercises MaxOpenConns=1 serialization under -race.
func TestSQLiteStoreConcurrent(t *testing.T) {
	s := newTestSQLiteStore(t)
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			if _, err := s.Create(HostInput{Name: "h" + strconv.Itoa(i), Hostname: "1.1.1.1"}); err != nil {
				t.Errorf("Create: %v", err)
			}
			if _, err := s.List(); err != nil {
				t.Errorf("List: %v", err)
			}
		}(i)
	}
	wg.Wait()
	hosts, _ := s.List()
	if len(hosts) != n {
		t.Errorf("len = %d, want %d", len(hosts), n)
	}
}
