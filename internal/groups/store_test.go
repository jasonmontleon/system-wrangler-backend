// SPDX-License-Identifier: Apache-2.0

package groups

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func newDeterministicMemStore() *MemStore {
	s := NewMemStore()
	var counter atomic.Int64
	s.NewID = func() string { return fmt.Sprintf("gid-%d", counter.Add(1)) }
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var tick atomic.Int64
	s.Now = func() time.Time {
		return base.Add(time.Duration(tick.Add(1)) * time.Second)
	}
	return s
}

func TestMemStoreCreateRoundTrip(t *testing.T) {
	s := newDeterministicMemStore()
	g, err := s.Create(GroupInput{Name: "  prod  "})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if g.Name != "prod" {
		t.Errorf("Name = %q, want trimmed 'prod'", g.Name)
	}
	if g.ID != "gid-1" {
		t.Errorf("ID = %q, want gid-1", g.ID)
	}
	if g.CreatedAt.Location() != time.UTC {
		t.Error("CreatedAt should be UTC")
	}
	got, err := s.Get(g.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "prod" {
		t.Errorf("Get name = %q", got.Name)
	}
}

func TestMemStoreCreateValidates(t *testing.T) {
	s := NewMemStore()
	if _, err := s.Create(GroupInput{Name: ""}); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty name: err = %v, want ErrInvalid", err)
	}
	long := make([]byte, maxNameLen+1)
	for i := range long {
		long[i] = 'x'
	}
	if _, err := s.Create(GroupInput{Name: string(long)}); !errors.Is(err, ErrInvalid) {
		t.Errorf("long name: err = %v, want ErrInvalid", err)
	}
}

func TestMemStoreCreateRejectsDuplicate(t *testing.T) {
	s := newDeterministicMemStore()
	if _, err := s.Create(GroupInput{Name: "prod"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Create(GroupInput{Name: "PROD"}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("case-insensitive duplicate: err = %v, want ErrDuplicate", err)
	}
}

func TestMemStoreListOrdered(t *testing.T) {
	s := newDeterministicMemStore()
	for _, n := range []string{"a", "b", "c"} {
		if _, err := s.Create(GroupInput{Name: n}); err != nil {
			t.Fatalf("Create %q: %v", n, err)
		}
	}
	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].CreatedAt.Before(got[i-1].CreatedAt) {
			t.Errorf("not ordered: %+v", got)
		}
	}
}

func TestMemStoreRename(t *testing.T) {
	s := newDeterministicMemStore()
	g, _ := s.Create(GroupInput{Name: "prod"})
	renamed, err := s.Rename(g.ID, GroupInput{Name: "production"})
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if renamed.Name != "production" {
		t.Errorf("Name = %q, want production", renamed.Name)
	}
	got, _ := s.Get(g.ID)
	if got.Name != "production" {
		t.Errorf("after Rename Get name = %q", got.Name)
	}
}

func TestMemStoreRenameMissing(t *testing.T) {
	s := newDeterministicMemStore()
	if _, err := s.Rename("nope", GroupInput{Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestMemStoreRenameRejectsDuplicate(t *testing.T) {
	s := newDeterministicMemStore()
	a, _ := s.Create(GroupInput{Name: "a"})
	if _, err := s.Create(GroupInput{Name: "b"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.Rename(a.ID, GroupInput{Name: "b"}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("err = %v, want ErrDuplicate", err)
	}
}

func TestMemStoreDeleteRunsCascade(t *testing.T) {
	s := newDeterministicMemStore()
	var called string
	s.OnDel = func(id string) { called = id }
	g, _ := s.Create(GroupInput{Name: "x"})
	if err := s.Delete(g.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if called != g.ID {
		t.Errorf("OnDel called with %q, want %q", called, g.ID)
	}
	if _, err := s.Get(g.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Delete Get err = %v, want ErrNotFound", err)
	}
}

func TestMemStoreDeleteMissing(t *testing.T) {
	s := newDeterministicMemStore()
	if err := s.Delete("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestMemStoreNilCounterIsZero(t *testing.T) {
	s := newDeterministicMemStore()
	s.Counter = nil
	g, _ := s.Create(GroupInput{Name: "x"})
	got, _ := s.Get(g.ID)
	if got.SystemCount != 0 {
		t.Errorf("SystemCount = %d, want 0", got.SystemCount)
	}
}

func TestMemStoreListPopulatesCount(t *testing.T) {
	s := newDeterministicMemStore()
	g1, _ := s.Create(GroupInput{Name: "g1"})
	g2, _ := s.Create(GroupInput{Name: "g2"})
	s.Counter = func() map[string]int {
		return map[string]int{g1.ID: 3, g2.ID: 0}
	}
	got, _ := s.List()
	counts := map[string]int{}
	for _, g := range got {
		counts[g.ID] = g.SystemCount
	}
	if counts[g1.ID] != 3 || counts[g2.ID] != 0 {
		t.Errorf("counts = %v, want g1=3 g2=0", counts)
	}
}
