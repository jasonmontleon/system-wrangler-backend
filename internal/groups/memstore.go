// SPDX-License-Identifier: Apache-2.0

package groups

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// MemberCounter returns the number of systems in each group. The groups
// MemStore doesn't track members itself — membership lives on the System
// struct in the systems package — so callers wire a snapshot function
// that reads the systems store. The result is keyed by group id.
type MemberCounter func() map[string]int

// GroupRemover is invoked on Delete so the systems store can null out any
// rows that pointed at the deleted group. Wired by the caller; nil is
// a no-op (useful for unit tests that don't care about cascade).
type GroupRemover func(groupID string)

// MemStore is an in-memory Store. Goroutine-safe. Data is lost on process
// exit; this matches the systems MemStore and is meant for tests.
type MemStore struct {
	mu     sync.RWMutex
	groups map[string]Group
	byName map[string]string

	NewID   func() string
	Now     func() time.Time
	Counter MemberCounter
	OnDel   GroupRemover
}

// NewMemStore returns an empty in-memory groups store. Counter defaults
// to "every group has zero members"; tests that care wire a real one.
func NewMemStore() *MemStore {
	return &MemStore{
		groups:  map[string]Group{},
		byName:  map[string]string{},
		NewID:   newUUID,
		Now:     time.Now,
		Counter: func() map[string]int { return map[string]int{} },
	}
}

// Create adds a new Group after running GroupInput.Validate. Returns
// ErrDuplicate if a group already exists with the same name.
func (s *MemStore) Create(in GroupInput) (Group, error) {
	if err := in.Validate(); err != nil {
		return Group{}, err
	}
	name := strings.TrimSpace(in.Name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byName[strings.ToLower(name)]; ok {
		return Group{}, ErrDuplicate
	}
	g := Group{
		ID:        s.NewID(),
		Name:      name,
		CreatedAt: s.Now().UTC(),
	}
	s.groups[g.ID] = g
	s.byName[strings.ToLower(name)] = g.ID
	return g, nil
}

// Get returns a single Group by ID, populated with its current SystemCount.
func (s *MemStore) Get(id string) (Group, error) {
	s.mu.RLock()
	g, ok := s.groups[id]
	s.mu.RUnlock()
	if !ok {
		return Group{}, ErrNotFound
	}
	g.SystemCount = s.countFor(id)
	return g, nil
}

// List returns all groups ordered by CreatedAt, ID tiebreaker, with
// SystemCount populated per group.
func (s *MemStore) List() ([]Group, error) {
	s.mu.RLock()
	out := make([]Group, 0, len(s.groups))
	for _, g := range s.groups {
		out = append(out, g)
	}
	s.mu.RUnlock()
	counts := s.snapshotCounts()
	for i := range out {
		out[i].SystemCount = counts[out[i].ID]
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// Rename updates the name of a group. Returns ErrDuplicate if another
// group already holds the new name.
func (s *MemStore) Rename(id string, in GroupInput) (Group, error) {
	if err := in.Validate(); err != nil {
		return Group{}, err
	}
	name := strings.TrimSpace(in.Name)
	key := strings.ToLower(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[id]
	if !ok {
		return Group{}, ErrNotFound
	}
	if other, exists := s.byName[key]; exists && other != id {
		return Group{}, ErrDuplicate
	}
	delete(s.byName, strings.ToLower(g.Name))
	g.Name = name
	s.groups[id] = g
	s.byName[key] = id
	g.SystemCount = s.countFor(id)
	return g, nil
}

// Delete removes a group, invoking OnDel (if set) so the systems store
// can cascade group_id to NULL.
func (s *MemStore) Delete(id string) error {
	s.mu.Lock()
	g, ok := s.groups[id]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	delete(s.groups, id)
	delete(s.byName, strings.ToLower(g.Name))
	s.mu.Unlock()
	if s.OnDel != nil {
		s.OnDel(id)
	}
	return nil
}

func (s *MemStore) snapshotCounts() map[string]int {
	if s.Counter == nil {
		return map[string]int{}
	}
	return s.Counter()
}

func (s *MemStore) countFor(id string) int {
	return s.snapshotCounts()[id]
}
