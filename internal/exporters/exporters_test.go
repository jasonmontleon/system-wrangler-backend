// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"errors"
	"strings"
	"testing"
)

func validDef() Definition {
	return Definition{
		ID:                  "custom.test",
		Source:              SourceCustom,
		DisplayName:         "Test",
		AppliesToPkgManager: "builtin.dnf",
		ExporterKind:        KindNodeExporter,
		BindPort:            9100,
		InstallPlaybook:     []byte("- hosts: all\n  tasks: []\n"),
		StatusPlaybook:      []byte("- hosts: all\n  tasks: []\n"),
	}
}

func TestDefinitionValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Definition)
		wantSub string
	}{
		{"valid", func(*Definition) {}, ""},
		{"no display name", func(d *Definition) { d.DisplayName = "" }, "display_name"},
		{"no pkg manager", func(d *Definition) { d.AppliesToPkgManager = "" }, "applies_to_pkg_manager required"},
		{"bad pkg manager shape", func(d *Definition) { d.AppliesToPkgManager = "dnf" }, "look like an updater id"},
		{"bad kind", func(d *Definition) { d.ExporterKind = "" }, "exporter_kind"},
		{"bad port lo", func(d *Definition) { d.BindPort = 0 }, "bind_port"},
		{"bad port hi", func(d *Definition) { d.BindPort = 70000 }, "bind_port"},
		{"no install", func(d *Definition) { d.InstallPlaybook = nil }, "install_playbook required"},
		{"no status", func(d *Definition) { d.StatusPlaybook = nil }, "status_playbook required"},
		{"install too big", func(d *Definition) {
			d.InstallPlaybook = make([]byte, MaxPlaybookBytes+1)
		}, "install_playbook exceeds"},
		{"status too big", func(d *Definition) {
			d.StatusPlaybook = make([]byte, MaxPlaybookBytes+1)
		}, "status_playbook exceeds"},
		{"remove too big", func(d *Definition) {
			d.RemovePlaybook = make([]byte, MaxPlaybookBytes+1)
		}, "remove_playbook exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := validDef()
			tc.mutate(&d)
			err := d.Validate()
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestDefinitionHasRemove(t *testing.T) {
	d := validDef()
	if d.HasRemove() {
		t.Errorf("blank remove should be false")
	}
	d.RemovePlaybook = []byte("- hosts: all\n  tasks: []\n")
	if !d.HasRemove() {
		t.Errorf("non-empty remove should be true")
	}
}

func TestExporterKindIsValid(t *testing.T) {
	if !KindNodeExporter.IsValid() || !KindWindowsExporter.IsValid() {
		t.Errorf("known kinds should validate")
	}
	if ExporterKind("blackbox").IsValid() {
		t.Errorf("unknown kind should not validate")
	}
}

func TestScrapeModeIsValid(t *testing.T) {
	for _, m := range []ScrapeMode{ScrapeLocalhost, ScrapeMTLSSelf, ScrapeMTLSByo} {
		if !m.IsValid() {
			t.Errorf("%q should validate", m)
		}
	}
	if ScrapeMode("nope").IsValid() {
		t.Errorf("unknown mode should not validate")
	}
}

func TestStateIsValid(t *testing.T) {
	for _, s := range []State{StateInstalled, StateRunning, StateFailed, StateRemoved} {
		if !s.IsValid() {
			t.Errorf("%q should validate", s)
		}
	}
	if State("nope").IsValid() {
		t.Errorf("unknown state should not validate")
	}
}

func TestRunKindIsValid(t *testing.T) {
	for _, k := range []RunKind{RunKindInstall, RunKindStatus, RunKindRemove} {
		if !k.IsValid() {
			t.Errorf("%q should validate", k)
		}
	}
	if RunKind("nope").IsValid() {
		t.Errorf("unknown kind should not validate")
	}
}

func TestIsBuiltinAndCustomID(t *testing.T) {
	if !IsBuiltinID("builtin.foo") || IsBuiltinID("custom.foo") {
		t.Errorf("IsBuiltinID mis-classified")
	}
	if !IsCustomID("custom.foo") || IsCustomID("builtin.foo") {
		t.Errorf("IsCustomID mis-classified")
	}
}

func TestSentinelErrorsAreDistinct(t *testing.T) {
	all := []error{ErrNotFound, ErrInvalid, ErrConflict, ErrBuiltinWrite, ErrReservedID, ErrDuplicate, ErrNoRemove}
	for i, a := range all {
		for j, b := range all {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("sentinel %v == %v", a, b)
			}
		}
	}
}
