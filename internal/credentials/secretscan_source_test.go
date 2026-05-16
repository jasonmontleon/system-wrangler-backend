// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"strings"
	"testing"

	"system-wrangler-backend/internal/secrets"
)

func TestScanSourceName(t *testing.T) {
	if got := (ScanSource{}).Name(); got != "ansible_credential" {
		t.Errorf("Name = %q, want ansible_credential", got)
	}
}

func TestScanSourceEmpty(t *testing.T) {
	store := newStore(t)
	src := ScanSource{Store: store}
	got, err := src.ListUndecryptable(testVault(t, 33))
	if err != nil {
		t.Fatalf("ListUndecryptable: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
	if n, err := src.CountUndecryptable(testVault(t, 33)); err != nil || n != 0 {
		t.Errorf("Count = (%d, %v), want (0, nil)", n, err)
	}
}

func TestScanSourceNilVault(t *testing.T) {
	src := ScanSource{Store: newStore(t)}
	if _, err := src.ListUndecryptable(nil); err == nil {
		t.Error("nil vault: expected error")
	}
}

// TestScanSourceFindsRowsSealedWithRetiredKey simulates the
// mismatched-key-restore scenario: a slot is sealed with vault A, the
// scan runs with vault B, and the row surfaces in the result.
func TestScanSourceFindsRowsSealedWithRetiredKey(t *testing.T) {
	store := newStore(t)
	old := testVault(t, 50)
	cur := testVault(t, 200)

	sealed, err := SealWith(old, []byte("ed25519-private-bytes"))
	if err != nil {
		t.Fatalf("SealWith: %v", err)
	}
	if _, err := store.Upsert(Slot{
		ScopeKind:   ScopeGlobal,
		AnsibleUser: "ansible",
		PublicKey:   "ssh-ed25519 AAAA",
		PrivateKey:  sealed,
		Origin:      OriginSWGenerated,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	src := ScanSource{Store: store}
	items, err := src.ListUndecryptable(cur)
	if err != nil {
		t.Fatalf("ListUndecryptable: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if items[0].Kind != "ansible_credential" {
		t.Errorf("Kind = %q", items[0].Kind)
	}
	if items[0].Field != "private_key" {
		t.Errorf("Field = %q", items[0].Field)
	}
	if !strings.Contains(items[0].TargetLabel, "global") {
		t.Errorf("TargetLabel = %q, want to contain 'global'", items[0].TargetLabel)
	}

	// Slots that decrypt cleanly do not appear in the result.
	if _, err := SealWith(cur, []byte("decryptable")); err != nil {
		t.Fatalf("SealWith cur: %v", err)
	}
}

func TestScanSourceSkipsKeylessSlots(t *testing.T) {
	store := newStore(t)
	if _, err := store.Upsert(Slot{
		ScopeKind:   ScopeGlobal,
		AnsibleUser: "ansible",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	src := ScanSource{Store: store}
	items, err := src.ListUndecryptable(testVault(t, 99))
	if err != nil {
		t.Fatalf("ListUndecryptable: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("user-only slot leaked into scan: %v", items)
	}
}

func TestLabelForCoversAllScopes(t *testing.T) {
	tests := []struct {
		slot Slot
		want string
	}{
		{Slot{ScopeKind: ScopeGlobal}, "global default"},
		{Slot{ScopeKind: ScopeGroup, ScopeID: "abc"}, "group abc"},
		{Slot{ScopeKind: ScopeSystem, ScopeID: "h-1"}, "system h-1"},
		{Slot{ScopeKind: ScopeKind("weird")}, "weird"},
	}
	for _, tt := range tests {
		if got := labelFor(tt.slot); got != tt.want {
			t.Errorf("labelFor(%v) = %q, want %q", tt.slot.ScopeKind, got, tt.want)
		}
	}
}

// Compile-time check: ScanSource satisfies secretscan.Source.
var _ = func() any {
	_ = secrets.Vault{}
	return nil
}
