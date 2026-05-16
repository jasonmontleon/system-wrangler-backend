// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"errors"
	"testing"
)

// memStore is a tiny in-memory Store for resolver tests. Keyed by
// (kind, scope_id) so the unique-per-scope invariant the SQLite
// store enforces is preserved here.
type memStore struct {
	slots map[string]Slot
}

func newMemStore() *memStore { return &memStore{slots: map[string]Slot{}} }

func memKey(kind ScopeKind, id string) string { return string(kind) + "|" + id }

func (m *memStore) put(slot Slot) {
	m.slots[memKey(slot.ScopeKind, slot.ScopeID)] = slot
}

func (m *memStore) GetByScope(kind ScopeKind, id string) (Slot, error) {
	if s, ok := m.slots[memKey(kind, id)]; ok {
		return s, nil
	}
	return Slot{}, ErrNotFound
}

func (m *memStore) List() ([]Slot, error) {
	out := make([]Slot, 0, len(m.slots))
	for _, s := range m.slots {
		out = append(out, s)
	}
	return out, nil
}

func (m *memStore) Upsert(s Slot) (Slot, error) { m.put(s); return s, nil }

func (m *memStore) Delete(kind ScopeKind, id string) error {
	if _, ok := m.slots[memKey(kind, id)]; !ok {
		return ErrNotFound
	}
	delete(m.slots, memKey(kind, id))
	return nil
}

// withKey is a test convenience for slots that need a key. Real
// callers go through SealWith; tests just need a non-zero Sealed
// triple so HasKey returns true.
func withKey(s Slot) Slot {
	s.PublicKey = "ssh-ed25519 AAAA-" + string(s.ScopeKind)
	s.PrivateKey = Sealed{Ciphertext: []byte{1}, Nonce: []byte{1}, Version: 1}
	if s.Origin == "" {
		s.Origin = OriginSWGenerated
	}
	return s
}

func TestResolveReturnsErrorWhenNothingSet(t *testing.T) {
	store := newMemStore()
	if _, err := Resolve(store, "host-1", strPtr("group-1")); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("err = %v, want ErrNoCredentials", err)
	}
}

func TestResolveRequiresSystemID(t *testing.T) {
	store := newMemStore()
	if _, err := Resolve(store, "", nil); err == nil {
		t.Error("expected error for empty systemID")
	}
}

func TestResolvePerFieldMerge(t *testing.T) {
	// The point of the resolver: a group can override the user
	// while inheriting the global key. Tests the per-field walk.
	store := newMemStore()
	store.put(withKey(Slot{
		ScopeKind:   ScopeGlobal,
		AnsibleUser: "global-user",
	}))
	store.put(Slot{
		ScopeKind:   ScopeGroup,
		ScopeID:     "group-prod",
		AnsibleUser: "prod-user",
	})
	got, err := Resolve(store, "host-A", strPtr("group-prod"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.AnsibleUser != "prod-user" {
		t.Errorf("user = %q, want prod-user", got.AnsibleUser)
	}
	if got.UserSource != ScopeGroup {
		t.Errorf("user source = %q, want group", got.UserSource)
	}
	if got.PublicKey != "ssh-ed25519 AAAA-global" {
		t.Errorf("public key = %q, want global", got.PublicKey)
	}
	if got.KeySource != ScopeGlobal {
		t.Errorf("key source = %q, want global", got.KeySource)
	}
	if got.KeyOrigin != OriginSWGenerated {
		t.Errorf("key origin = %q, want sw_generated", got.KeyOrigin)
	}
}

func TestResolveSystemOverridesGroup(t *testing.T) {
	store := newMemStore()
	store.put(withKey(Slot{ScopeKind: ScopeGlobal, AnsibleUser: "u-global"}))
	store.put(withKey(Slot{ScopeKind: ScopeGroup, ScopeID: "g-1", AnsibleUser: "u-group"}))
	store.put(withKey(Slot{ScopeKind: ScopeSystem, ScopeID: "host-X", AnsibleUser: "u-system", Origin: OriginUserSupplied}))

	got, err := Resolve(store, "host-X", strPtr("g-1"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.AnsibleUser != "u-system" || got.UserSource != ScopeSystem {
		t.Errorf("user = (%q, %q), want (u-system, system)", got.AnsibleUser, got.UserSource)
	}
	if got.KeySource != ScopeSystem {
		t.Errorf("key source = %q, want system", got.KeySource)
	}
	if got.KeyOrigin != OriginUserSupplied {
		t.Errorf("key origin = %q, want user_supplied", got.KeyOrigin)
	}
}

func TestResolveUngroupedSystemSkipsGroupLevel(t *testing.T) {
	// An ungrouped system (nil group_id) falls through to global
	// directly; the group level is skipped, not errored on.
	store := newMemStore()
	store.put(withKey(Slot{ScopeKind: ScopeGlobal, AnsibleUser: "u"}))
	got, err := Resolve(store, "host-loose", nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.UserSource != ScopeGlobal || got.KeySource != ScopeGlobal {
		t.Errorf("sources = (%q, %q), want (global, global)", got.UserSource, got.KeySource)
	}
}

func TestResolveIncompleteFlow(t *testing.T) {
	// Only a user is set (no key anywhere). The system is reachable
	// in name only — resolver returns ErrIncompleteFlow so a UI can
	// say "set a key before this can run."
	store := newMemStore()
	store.put(Slot{ScopeKind: ScopeGlobal, AnsibleUser: "u"})
	if _, err := Resolve(store, "host-1", nil); !errors.Is(err, ErrIncompleteFlow) {
		t.Errorf("err = %v, want ErrIncompleteFlow", err)
	}
}

func TestResolveSurfacesStoreError(t *testing.T) {
	store := &errStore{err: errors.New("boom")}
	if _, err := Resolve(store, "host", nil); err == nil {
		t.Error("expected store error to surface")
	}
}

type errStore struct{ err error }

func (e *errStore) GetByScope(ScopeKind, string) (Slot, error) { return Slot{}, e.err }
func (e *errStore) List() ([]Slot, error)                      { return nil, e.err }
func (e *errStore) Upsert(s Slot) (Slot, error)                { return s, e.err }
func (e *errStore) Delete(ScopeKind, string) error             { return e.err }

func strPtr(s string) *string { return &s }
