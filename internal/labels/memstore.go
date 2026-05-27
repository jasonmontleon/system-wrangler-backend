// SPDX-License-Identifier: Apache-2.0

package labels

import (
	"sort"
	"sync"
)

// SystemExists is a callback the MemStore uses to enforce the FK to the
// systems table; pass nil for tests that don't care. Returning false
// from this callback causes Set to fail with ErrNotFound, mirroring the
// SQLite ON DELETE CASCADE referential check.
type SystemExists func(systemID string) bool

// MemStore is an in-memory Store. Goroutine-safe, lossy on exit,
// intended for unit tests.
type MemStore struct {
	mu     sync.RWMutex
	bySys  map[string]map[string]*string
	Exists SystemExists
}

// NewMemStore returns an empty in-memory store. Exists defaults to "any
// system_id is valid" so simple tests don't need to wire it.
func NewMemStore() *MemStore {
	return &MemStore{
		bySys:  map[string]map[string]*string{},
		Exists: func(string) bool { return true },
	}
}

// Set inserts or overwrites a label. Returns ErrNotFound when the
// Exists callback rejects the system_id.
func (s *MemStore) Set(systemID, key string, value *string, allowReserved bool) (Label, error) {
	if systemID == "" {
		return Label{}, ErrInvalid
	}
	if err := ValidateKey(key, allowReserved); err != nil {
		return Label{}, err
	}
	if err := ValidateValue(value); err != nil {
		return Label{}, err
	}
	if s.Exists != nil && !s.Exists(systemID) {
		return Label{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.bySys[systemID]
	if !ok {
		m = map[string]*string{}
		s.bySys[systemID] = m
	}
	m[key] = copyVal(value)
	return Label{Key: key, Value: copyVal(value)}, nil
}

// Delete removes a label. Returns ErrNotFound if the row does not exist.
func (s *MemStore) Delete(systemID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.bySys[systemID]
	if !ok {
		return ErrNotFound
	}
	if _, ok := m[key]; !ok {
		return ErrNotFound
	}
	delete(m, key)
	if len(m) == 0 {
		delete(s.bySys, systemID)
	}
	return nil
}

// ForSystem returns the system's labels sorted by key.
func (s *MemStore) ForSystem(systemID string) ([]Label, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.bySys[systemID]
	out := make([]Label, 0, len(m))
	for k, v := range m {
		out = append(out, Label{Key: k, Value: copyVal(v)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// ForSystems bulk-loads labels for the given system IDs.
func (s *MemStore) ForSystems(systemIDs []string) (map[string][]Label, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]Label, len(systemIDs))
	for _, sid := range systemIDs {
		m := s.bySys[sid]
		if len(m) == 0 {
			continue
		}
		ls := make([]Label, 0, len(m))
		for k, v := range m {
			ls = append(ls, Label{Key: k, Value: copyVal(v)})
		}
		sort.Slice(ls, func(i, j int) bool { return ls[i].Key < ls[j].Key })
		out[sid] = ls
	}
	return out, nil
}

// Summary collapses bare-tag rows under Value==nil and counts each
// (key, value) pair across all systems.
func (s *MemStore) Summary() ([]KeySummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	type vk struct {
		key string
		val string
		nil bool
	}
	counts := map[vk]int{}
	for _, m := range s.bySys {
		for k, v := range m {
			entry := vk{key: k}
			if v == nil {
				entry.nil = true
			} else {
				entry.val = *v
			}
			counts[entry]++
		}
	}
	byKey := map[string]*KeySummary{}
	for k, n := range counts {
		ks, ok := byKey[k.key]
		if !ok {
			ks = &KeySummary{Key: k.key}
			byKey[k.key] = ks
		}
		vs := ValueSummary{Count: n}
		if !k.nil {
			v := k.val
			vs.Value = &v
		}
		ks.Values = append(ks.Values, vs)
		ks.Count += n
	}
	out := make([]KeySummary, 0, len(byKey))
	for _, ks := range byKey {
		sort.Slice(ks.Values, func(i, j int) bool {
			return valueSortKey(ks.Values[i].Value) < valueSortKey(ks.Values[j].Value)
		})
		out = append(out, *ks)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// valueSortKey returns a string that sorts nil-valued entries first to
// match the SQLite ORDER BY semantics (NULL sorts before any string).
func valueSortKey(v *string) string {
	if v == nil {
		return ""
	}
	return "\x01" + *v
}

func copyVal(v *string) *string {
	if v == nil {
		return nil
	}
	s := *v
	return &s
}

var _ Store = (*MemStore)(nil)
