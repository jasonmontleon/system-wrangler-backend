// SPDX-License-Identifier: AGPL-3.0-or-later

package inventory

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Store is the persistence boundary for hosts. Swapping implementations
// (SQLite, Postgres, etc.) should not require handler changes.
type Store interface {
	Create(in HostInput) (Host, error)
	Get(id string) (Host, error)
	List() ([]Host, error)
	Delete(id string) error
	// UpdateProbe records a probe outcome. when is the timestamp the probe
	// completed; on success it also becomes the host's LastSeen.
	UpdateProbe(id string, ok bool, when time.Time) error
}

// MemStore is an in-memory Store. Safe for concurrent use. Data is lost on
// process exit; this is intentional until a backing store is chosen.
type MemStore struct {
	mu    sync.RWMutex
	hosts map[string]Host

	// NewID and Now are injectable for deterministic tests. Defaults are set
	// by NewMemStore.
	NewID func() string
	Now   func() time.Time
}

func NewMemStore() *MemStore {
	return &MemStore{
		hosts: map[string]Host{},
		NewID: newUUID,
		Now:   time.Now,
	}
}

func (s *MemStore) Create(in HostInput) (Host, error) {
	if err := in.Validate(); err != nil {
		return Host{}, err
	}
	h := Host{
		ID:        s.NewID(),
		Name:      strings.TrimSpace(in.Name),
		Hostname:  strings.TrimSpace(in.Hostname),
		CreatedAt: s.Now().UTC(),
		Status:    StatusUnprobed,
	}
	s.mu.Lock()
	s.hosts[h.ID] = h
	s.mu.Unlock()
	return h, nil
}

func (s *MemStore) Get(id string) (Host, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.hosts[id]
	if !ok {
		return Host{}, ErrNotFound
	}
	return h, nil
}

// List returns hosts ordered by CreatedAt ascending, ID as tiebreaker so the
// order is stable across calls regardless of map iteration.
func (s *MemStore) List() ([]Host, error) {
	s.mu.RLock()
	out := make([]Host, 0, len(s.hosts))
	for _, h := range s.hosts {
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

func (s *MemStore) UpdateProbe(id string, ok bool, when time.Time) error {
	when = when.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.hosts[id]
	if !found {
		return ErrNotFound
	}
	if ok {
		h.Status = StatusReachable
		h.LastSeen = &when
	} else {
		h.Status = StatusUnreachable
	}
	s.hosts[id] = h
	return nil
}

func (s *MemStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[id]; !ok {
		return ErrNotFound
	}
	delete(s.hosts, id)
	return nil
}
