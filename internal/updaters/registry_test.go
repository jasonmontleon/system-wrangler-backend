// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"errors"
	"testing"
	"time"
)

func TestRegistryAllUnionsBuiltinsAndCustom(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)
	all, err := reg.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	hasDNF := false
	for _, d := range all {
		if d.ID == "builtin.dnf" {
			if d.Source != SourceBuiltin {
				t.Errorf("dnf builtin source = %q, want builtin", d.Source)
			}
			if len(d.CheckPlaybook) == 0 || len(d.ApplyPlaybook) == 0 {
				t.Errorf("dnf builtin missing embedded body")
			}
			hasDNF = true
		}
	}
	if !hasDNF {
		t.Fatalf("builtin.dnf not in registry: %+v", all)
	}
	// Add a custom row and confirm it shows up.
	if _, err := reg.CreateCustom(sampleDef("custom.alpha")); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	all, _ = reg.All()
	names := map[string]bool{}
	for _, d := range all {
		names[d.ID] = true
	}
	if !names["builtin.dnf"] || !names["custom.alpha"] {
		t.Errorf("registry missing entries: %+v", names)
	}
}

func TestRegistryGetBuiltin(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)
	d, err := reg.Get("builtin.dnf")
	if err != nil {
		t.Fatalf("Get builtin.dnf: %v", err)
	}
	if d.Source != SourceBuiltin || d.ID != "builtin.dnf" {
		t.Errorf("unexpected definition: %+v", d)
	}
}

func TestBuiltinsShipExpectedSet(t *testing.T) {
	want := map[string]string{
		"builtin.dnf":            "dnf",
		"builtin.apt":            "apt",
		"builtin.snap":           "snap",
		"builtin.flatpak":        "flatpak",
		"builtin.pacman":         "pacman",
		"builtin.zypper":         "zypper",
		"builtin.apk":            "apk",
		"builtin.pkg":            "pkg",
		"builtin.pkg_add":        "pkg_add",
		"builtin.pkgin":          "pkgin",
		"builtin.winget":         "winget",
		"builtin.xbps":           "xbps-install",
		"builtin.eopkg":          "eopkg",
		"builtin.brew":           "brew",
		"builtin.mas":            "mas",
		"builtin.softwareupdate": "softwareupdate",
	}
	got := map[string]Definition{}
	for _, d := range Builtins() {
		got[d.ID] = d
	}
	if len(got) != len(want) {
		t.Errorf("builtin count = %d, want %d", len(got), len(want))
	}
	for id, binary := range want {
		d, ok := got[id]
		if !ok {
			t.Errorf("missing builtin %q", id)
			continue
		}
		if d.Source != SourceBuiltin {
			t.Errorf("%s.Source = %q, want builtin", id, d.Source)
		}
		if d.DetectBinary != binary {
			t.Errorf("%s.DetectBinary = %q, want %q", id, d.DetectBinary, binary)
		}
		if len(d.CheckPlaybook) == 0 {
			t.Errorf("%s.CheckPlaybook is empty (embed failed?)", id)
		}
		if len(d.ApplyPlaybook) == 0 {
			t.Errorf("%s.ApplyPlaybook is empty (embed failed?)", id)
		}
	}
}

func TestRegistryGetCustomIncludesSoftDeleted(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)
	if _, err := reg.CreateCustom(sampleDef("custom.zeta")); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	if err := reg.DeleteCustom("custom.zeta", time.Now()); err != nil {
		t.Fatalf("DeleteCustom: %v", err)
	}
	d, err := reg.Get("custom.zeta")
	if err != nil {
		t.Fatalf("Get on deleted: %v", err)
	}
	if !d.IsDeleted() {
		t.Errorf("expected deleted tombstone on Get of soft-deleted")
	}
	// All() must skip it.
	all, _ := reg.All()
	for _, x := range all {
		if x.ID == "custom.zeta" {
			t.Errorf("All() returned soft-deleted: %+v", x)
		}
	}
}

func TestRegistryRejectsBuiltinWrites(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)
	d := sampleDef("builtin.dnf")
	if _, err := reg.CreateCustom(d); !errors.Is(err, ErrReservedID) {
		t.Errorf("CreateCustom: err = %v, want ErrReservedID", err)
	}
	if _, err := reg.UpdateCustom(d); !errors.Is(err, ErrBuiltinWrite) {
		t.Errorf("UpdateCustom: err = %v, want ErrBuiltinWrite", err)
	}
	if err := reg.DeleteCustom("builtin.dnf", time.Now()); !errors.Is(err, ErrBuiltinWrite) {
		t.Errorf("DeleteCustom: err = %v, want ErrBuiltinWrite", err)
	}
}

func TestRegistryGetUnknownID(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)
	if _, err := reg.Get("builtin.nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get unknown builtin: err = %v, want ErrNotFound", err)
	}
	if _, err := reg.Get("custom.nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get unknown custom: err = %v, want ErrNotFound", err)
	}
	if _, err := reg.Get("no-prefix"); !errors.Is(err, ErrInvalid) {
		t.Errorf("Get prefixless: err = %v, want ErrInvalid", err)
	}
}

func TestDefinitionValidate(t *testing.T) {
	good := sampleDef("custom.x")
	if err := good.Validate(); err != nil {
		t.Errorf("good Validate: %v", err)
	}
	tests := []struct {
		name string
		mut  func(*Definition)
	}{
		{"no display", func(d *Definition) { d.DisplayName = "" }},
		{"no binary", func(d *Definition) { d.DetectBinary = "" }},
		{"no check", func(d *Definition) { d.CheckPlaybook = nil }},
		{"no apply", func(d *Definition) { d.ApplyPlaybook = nil }},
		{"check too big", func(d *Definition) { d.CheckPlaybook = make([]byte, MaxPlaybookBytes+1) }},
		{"apply too big", func(d *Definition) { d.ApplyPlaybook = make([]byte, MaxPlaybookBytes+1) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := sampleDef("custom.x")
			tt.mut(&d)
			if err := d.Validate(); err == nil {
				t.Errorf("Validate returned nil, want error")
			}
		})
	}
}
