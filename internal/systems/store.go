// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"database/sql"
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
	// CreateTx is the in-transaction sibling of Create. The handler uses
	// it to land the new row in the same transaction as the audit_log
	// row that records the operation, so the change and its audit row
	// commit together or neither commits. tx may be nil — implementations
	// that do not have a real transaction (MemStore) delegate to Create.
	CreateTx(tx *sql.Tx, in SystemInput) (System, error)
	// DeleteTx is the in-transaction sibling of Delete. Same contract as
	// CreateTx.
	DeleteTx(tx *sql.Tx, id string) error
	// UpdateProbe records a probe outcome and applies the threshold-
	// based state machine. ok=true bumps ConsecutiveSuccesses and
	// resets ConsecutiveFailures; ok=false bumps ConsecutiveFailures
	// and resets ConsecutiveSuccesses. Status flips to reachable only
	// after ConsecutiveSuccesses >= succThreshold, and to unreachable
	// only after ConsecutiveFailures >= failThreshold. The returned
	// bool is true when the call caused a Status transition (so the
	// caller can fire change notifications without a re-read).
	// LastSeen is updated on every success regardless of the
	// threshold (per-probe "last contact" is independent of "are we
	// declaring this system reachable yet").
	UpdateProbe(id string, ok bool, when time.Time, failThreshold, succThreshold int) (transitioned bool, err error)
	// SetGroup assigns a system to a group, or clears its group when
	// groupID is nil. Returns ErrNotFound if the system does not exist.
	// FK integrity (does the group exist?) is enforced by the groups
	// table when present; SetGroup itself does not validate it.
	SetGroup(systemID string, groupID *string) error
	// SetPlatform updates the IsWindows flag for the system. Returns
	// ErrNotFound if the system does not exist.
	SetPlatform(systemID string, isWindows bool) error
	// SetPlatformTx is the in-transaction sibling of SetPlatform so the
	// row mutation and the accompanying audit row commit together.
	SetPlatformTx(tx *sql.Tx, systemID string, isWindows bool) error
	// SetPlatformInfo persists the detected platform facts the
	// inspect playbook reports. Empty strings are valid values —
	// they correspond to "not detected yet" / "bare metal". The
	// operator-set IsWindows flag is intentionally not touched here;
	// platform intent and platform detection are independent.
	SetPlatformInfo(systemID, osFamily, osDistribution, virtualization string) error
	// SetRebootRequired records the timestamp of the apply that
	// flipped the host into needs-reboot state.
	SetRebootRequired(systemID string, at time.Time) error
	// ClearRebootRequired nils the reboot-required timestamp. Called
	// when a structurally-successful run completes without
	// re-emitting the SW_REBOOT_REQUIRED marker.
	ClearRebootRequired(systemID string) error
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

// UpdateProbe applies the threshold-based reachability state
// machine. See Store.UpdateProbe for semantics. The transitioned
// bool reflects whether Status itself changed on this call.
func (s *MemStore) UpdateProbe(id string, ok bool, when time.Time, failThreshold, succThreshold int) (bool, error) {
	when = when.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.systems[id]
	if !found {
		return false, ErrNotFound
	}
	prevStatus := h.Status
	if ok {
		h.ConsecutiveSuccesses++
		h.ConsecutiveFailures = 0
		h.LastSeen = &when
		if h.ConsecutiveSuccesses >= succThreshold && h.Status != StatusReachable {
			h.Status = StatusReachable
		}
	} else {
		h.ConsecutiveFailures++
		h.ConsecutiveSuccesses = 0
		if h.ConsecutiveFailures >= failThreshold && h.Status != StatusUnreachable {
			h.Status = StatusUnreachable
		}
	}
	s.systems[id] = h
	return prevStatus != h.Status, nil
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

// CreateTx delegates to Create. MemStore has no real transactions; the tx
// argument is accepted for interface parity with SQLiteStore.
func (s *MemStore) CreateTx(_ *sql.Tx, in SystemInput) (System, error) {
	return s.Create(in)
}

// DeleteTx delegates to Delete for the same reason as CreateTx.
func (s *MemStore) DeleteTx(_ *sql.Tx, id string) error {
	return s.Delete(id)
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

// SetPlatformTx delegates to SetPlatform. MemStore has no real
// transactions; the tx argument is accepted for interface parity.
func (s *MemStore) SetPlatformTx(_ *sql.Tx, systemID string, isWindows bool) error {
	return s.SetPlatform(systemID, isWindows)
}

// SetPlatform flips the IsWindows flag on the system.
func (s *MemStore) SetPlatform(systemID string, isWindows bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.systems[systemID]
	if !found {
		return ErrNotFound
	}
	h.IsWindows = isWindows
	s.systems[systemID] = h
	return nil
}

// SetPlatformInfo persists detected platform facts on the system.
func (s *MemStore) SetPlatformInfo(systemID, osFamily, osDistribution, virtualization string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.systems[systemID]
	if !found {
		return ErrNotFound
	}
	h.OSFamily = osFamily
	h.OSDistribution = osDistribution
	h.Virtualization = virtualization
	s.systems[systemID] = h
	return nil
}

// SetRebootRequired stamps the reboot-required timestamp on the
// system.
func (s *MemStore) SetRebootRequired(systemID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.systems[systemID]
	if !found {
		return ErrNotFound
	}
	t := at.UTC()
	h.RebootRequiredAt = &t
	s.systems[systemID] = h
	return nil
}

// ClearRebootRequired nils RebootRequiredAt.
func (s *MemStore) ClearRebootRequired(systemID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, found := s.systems[systemID]
	if !found {
		return ErrNotFound
	}
	h.RebootRequiredAt = nil
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
