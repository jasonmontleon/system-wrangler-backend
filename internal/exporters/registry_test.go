// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"errors"
	"testing"
	"time"
)

func TestRegistryAllUnionsBuiltinsAndCustom(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)

	defs, err := reg.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(defs) < 1 {
		t.Fatalf("expected at least one builtin; got %d", len(defs))
	}
	foundBuiltin := false
	for _, d := range defs {
		if d.ID == "builtin.dnf.exporter" {
			foundBuiltin = true
			if d.Source != SourceBuiltin {
				t.Errorf("dnf source = %q, want builtin", d.Source)
			}
		}
	}
	if !foundBuiltin {
		t.Errorf("dnf builtin missing from registry")
	}

	d := validDef()
	d.ID = "custom.alpha"
	if _, err := reg.CreateCustom(d); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	defs, err = reg.All()
	if err != nil {
		t.Fatalf("All after create: %v", err)
	}
	found := false
	for _, d := range defs {
		if d.ID == "custom.alpha" {
			found = true
			if d.Source != SourceCustom {
				t.Errorf("custom source = %q, want custom", d.Source)
			}
		}
	}
	if !found {
		t.Errorf("custom.alpha not surfaced by All")
	}
}

func TestRegistryGetBuiltin(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)
	d, err := reg.Get("builtin.dnf.exporter")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if d.ExporterKind != KindNodeExporter {
		t.Errorf("kind = %q, want node_exporter", d.ExporterKind)
	}
	if d.BindPort != 9100 {
		t.Errorf("port = %d, want 9100", d.BindPort)
	}
}

func TestRegistryGetUnknown(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)
	if _, err := reg.Get("nope"); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
	if _, err := reg.Get("builtin.nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestRegistryRejectsBuiltinMutations(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)
	if _, err := reg.CreateCustom(Definition{ID: "builtin.x"}); !errors.Is(err, ErrReservedID) {
		t.Errorf("create err = %v, want ErrReservedID", err)
	}
	if _, err := reg.UpdateCustom(Definition{ID: "builtin.x"}); !errors.Is(err, ErrBuiltinWrite) {
		t.Errorf("update err = %v, want ErrBuiltinWrite", err)
	}
	if err := reg.DeleteCustom("builtin.x", time.Now()); !errors.Is(err, ErrBuiltinWrite) {
		t.Errorf("delete err = %v, want ErrBuiltinWrite", err)
	}
	if err := reg.DeleteCustom("noprefix", time.Now()); !errors.Is(err, ErrInvalid) {
		t.Errorf("delete err = %v, want ErrInvalid", err)
	}
}

func TestBuiltinsShipExpectedSet(t *testing.T) {
	got := Builtins()
	if len(got) == 0 {
		t.Fatal("Builtins returned no entries")
	}
	want := map[string]bool{"builtin.dnf.exporter": true}
	seen := map[string]bool{}
	for _, b := range got {
		seen[b.ID] = true
		if len(b.InstallPlaybook) == 0 || len(b.StatusPlaybook) == 0 {
			t.Errorf("builtin %q missing install or status body", b.ID)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("missing builtin %q", id)
		}
	}
}
