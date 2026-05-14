// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestStore returns a MemStore with deterministic IDs and clock so tests
// can assert exact values.
func newTestStore() *MemStore {
	s := NewMemStore()
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

func TestMemStoreCreateAndGet(t *testing.T) {
	s := newTestStore()
	h, err := s.Create(SystemInput{Name: "  host1 ", Hostname: " 10.0.0.1 "})
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
	if got != h {
		t.Errorf("Get returned %+v, want %+v", got, h)
	}
}

func TestMemStoreCreateInvalid(t *testing.T) {
	s := newTestStore()
	_, err := s.Create(SystemInput{Name: "", Hostname: "1.2.3.4"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	systems, _ := s.List()
	if len(systems) != 0 {
		t.Errorf("invalid create should not persist; got %d systems", len(systems))
	}
}

func TestMemStoreGetMissing(t *testing.T) {
	s := newTestStore()
	if _, err := s.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestMemStoreListOrdered(t *testing.T) {
	s := newTestStore()
	for i := 0; i < 3; i++ {
		if _, err := s.Create(SystemInput{Name: "h" + strconv.Itoa(i), Hostname: "1.1.1.1"}); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	systems, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(systems) != 3 {
		t.Fatalf("len = %d, want 3", len(systems))
	}
	for i := 1; i < len(systems); i++ {
		if systems[i].CreatedAt.Before(systems[i-1].CreatedAt) {
			t.Errorf("systems not ordered by CreatedAt: %+v", systems)
		}
	}
}

func TestMemStoreDelete(t *testing.T) {
	s := newTestStore()
	h, _ := s.Create(SystemInput{Name: "h", Hostname: "1.1.1.1"})
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

func TestMemStoreUpdateProbe(t *testing.T) {
	s := newTestStore()
	h, _ := s.Create(SystemInput{Name: "h", Hostname: "1.1.1.1"})
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

func TestMemStoreUpdateProbeMissing(t *testing.T) {
	s := newTestStore()
	if err := s.UpdateProbe("nope", true, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestMemStoreSetGroupRoundTrip(t *testing.T) {
	s := newTestStore()
	h, _ := s.Create(SystemInput{Name: "h", Hostname: "1.1.1.1"})
	gid := "g-1"
	if err := s.SetGroup(h.ID, &gid); err != nil {
		t.Fatalf("SetGroup assign: %v", err)
	}
	got, _ := s.Get(h.ID)
	if got.GroupID == nil || *got.GroupID != gid {
		t.Errorf("GroupID = %v, want %q", got.GroupID, gid)
	}
	if err := s.SetGroup(h.ID, nil); err != nil {
		t.Fatalf("SetGroup clear: %v", err)
	}
	got, _ = s.Get(h.ID)
	if got.GroupID != nil {
		t.Errorf("after clear GroupID = %v, want nil", got.GroupID)
	}
}

func TestMemStoreSetGroupMissing(t *testing.T) {
	s := newTestStore()
	gid := "g-1"
	if err := s.SetGroup("nope", &gid); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestMemStoreClearGroup(t *testing.T) {
	s := newTestStore()
	a, _ := s.Create(SystemInput{Name: "a", Hostname: "1.1.1.1"})
	b, _ := s.Create(SystemInput{Name: "b", Hostname: "1.1.1.2"})
	gid := "g-1"
	if err := s.SetGroup(a.ID, &gid); err != nil {
		t.Fatalf("SetGroup a: %v", err)
	}
	if err := s.SetGroup(b.ID, &gid); err != nil {
		t.Fatalf("SetGroup b: %v", err)
	}
	s.ClearGroup(gid)
	gotA, _ := s.Get(a.ID)
	gotB, _ := s.Get(b.ID)
	if gotA.GroupID != nil || gotB.GroupID != nil {
		t.Errorf("ClearGroup didn't clear: a=%v b=%v", gotA.GroupID, gotB.GroupID)
	}
}

// TestMemStoreConcurrent exercises the RWMutex under -race; it does not
// assert specific output beyond "no race / no panic / all writes visible".
func TestMemStoreConcurrent(t *testing.T) {
	s := NewMemStore()
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			if _, err := s.Create(SystemInput{Name: "h" + strconv.Itoa(i), Hostname: "1.1.1.1"}); err != nil {
				t.Errorf("Create: %v", err)
			}
			if _, err := s.List(); err != nil {
				t.Errorf("List: %v", err)
			}
		}(i)
	}
	wg.Wait()
	systems, _ := s.List()
	if len(systems) != n {
		t.Errorf("len = %d, want %d", len(systems), n)
	}
}
