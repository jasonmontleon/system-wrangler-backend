// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Store is the persistence boundary for systems. Swapping implementations
// (SQLite, Postgres, etc.) should not require handler changes.
type Store interface {
	Create(in SystemInput) (System, error)
	Get(id string) (System, error)
	List() ([]System, error)
	Delete(id string) error
	// UpdateProbe records a probe outcome. when is the timestamp the probe
	// completed; on success it also becomes the system's LastSeen.
	UpdateProbe(id string, ok bool, when time.Time) error
	// SetGroup assigns a system to a group, or clears its group when
	// groupID is nil. Returns ErrNotFound if the system does not exist.
	// FK integrity (does the group exist?) is enforced by the groups
	// table when present; SetGroup itself does not validate it.
	SetGroup(systemID string, groupID *string) error
}

// MemStore is an in-memory Store. Safe for concurrent use. Data is lost on
// process exit; this is intentional until a backing store is chosen.
type MemStore struct {
	mu      sync.RWMutex
	systems map[string]System

	// NewID and Now are injectable for deterministic tests. Defaults are set
	// by NewMemStore.
	NewID func() string
	Now   func() time.Time
}

// NewMemStore returns an empty in-memory store with default ID/clock.
func NewMemStore() *MemStore {
	return &MemStore{
		systems: map[string]System{},
		NewID:   newUUID,
		Now:     time.Now,
	}
}

// Create adds a new System after running SystemInput.Validate.
func (s *MemStore) Create(in SystemInput) (System, error) {
	if err := in.Validate(); err != nil {
		return System{}, err
	}
	h := System{
		ID:        s.NewID(),
		Name:      strings.TrimSpace(in.Name),
		Hostname:  strings.TrimSpace(in.Hostname),
		CreatedAt: s.Now().UTC(),
		Status:    StatusUnprobed,
	}
	s.mu.Lock()
	s.systems[h.ID] = h
	s.mu.Unlock()
	return h, nil
}

// Get returns the System with the given ID, or ErrNotFound.
func (s *MemStore) Get(id string) (System, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.systems[id]
	if !ok {
		return System{}, ErrNotFound
	}
	return h, nil
}

// List returns systems ordered by CreatedAt ascending, ID as tiebreaker so the
// order is stable across calls regardless of map iteration.
func (s *MemStore) List() ([]System, error) {
	s.mu.RLock()
	out := make([]System, 0, len(s.systems))
	for _, h := range s.systems {
		out = append(out, h)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// UpdateProbe records a probe result against id. ok=true sets Status to
// reachable and updates LastSeen; ok=false sets Status to unreachable and
// preserves any prior LastSeen.
func (s *MemStore) UpdateProbe(id string, ok bool, when time.Time) error {
	when = when.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.systems[id]
	if !found {
		return ErrNotFound
	}
	if ok {
		h.Status = StatusReachable
		h.LastSeen = &when
	} else {
		h.Status = StatusUnreachable
	}
	s.systems[id] = h
	return nil
}

// Delete removes the System with the given ID, or returns ErrNotFound.
func (s *MemStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.systems[id]; !ok {
		return ErrNotFound
	}
	delete(s.systems, id)
	return nil
}

// SetGroup assigns the system to a group, or clears the assignment when
// groupID is nil.
func (s *MemStore) SetGroup(systemID string, groupID *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.systems[systemID]
	if !found {
		return ErrNotFound
	}
	if groupID == nil {
		h.GroupID = nil
	} else {
		v := *groupID
		h.GroupID = &v
	}
	s.systems[systemID] = h
	return nil
}

// ClearGroup nils out the GroupID on every system whose current GroupID
// matches groupID. Used by the groups store on Delete so MemStore-backed
// tests see the same cascade behavior as SQLite.
func (s *MemStore) ClearGroup(groupID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, h := range s.systems {
		if h.GroupID != nil && *h.GroupID == groupID {
			h.GroupID = nil
			s.systems[id] = h
		}
	}
}
