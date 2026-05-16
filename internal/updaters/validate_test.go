// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"errors"
	"testing"
	"time"
)

func TestRunKindIsValid(t *testing.T) {
	good := []RunKind{RunKindInspect, RunKindCheck, RunKindApply}
	for _, k := range good {
		if !k.IsValid() {
			t.Errorf("%q reported invalid", k)
		}
	}
	if RunKind("nope").IsValid() {
		t.Errorf("bogus kind reported valid")
	}
}

func TestIDPrefixHelpers(t *testing.T) {
	if !IsBuiltinID("builtin.dnf") {
		t.Error("builtin.dnf not identified as builtin")
	}
	if IsBuiltinID("custom.dnf") {
		t.Error("custom.dnf misidentified as builtin")
	}
	if !IsCustomID("custom.alpha") {
		t.Error("custom.alpha not identified as custom")
	}
	if IsCustomID("builtin.dnf") {
		t.Error("builtin.dnf misidentified as custom")
	}
}

func TestNewUUIDShape(t *testing.T) {
	id := newUUID()
	if len(id) != 36 {
		t.Errorf("uuid length = %d, want 36", len(id))
	}
}

func TestUpdateCustomRejectsBuiltinPrefix(t *testing.T) {
	store := newStore(t)
	d := sampleDef("builtin.dnf")
	if _, err := store.UpdateCustom(d); !errors.Is(err, ErrReservedID) {
		t.Errorf("err = %v, want ErrReservedID", err)
	}
}

func TestUpdateCustomValidationFails(t *testing.T) {
	store := newStore(t)
	if _, err := store.CreateCustom(sampleDef("custom.x")); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	d := sampleDef("custom.x")
	d.DisplayName = ""
	if _, err := store.UpdateCustom(d); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestCreateCustomValidationFails(t *testing.T) {
	store := newStore(t)
	d := sampleDef("custom.bad")
	d.CheckPlaybook = nil
	if _, err := store.CreateCustom(d); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestUpsertAvailabilityRejectsEmpty(t *testing.T) {
	store := newStore(t)
	if err := store.UpsertAvailability("", "builtin.dnf", time.Now()); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty system: err = %v, want ErrInvalid", err)
	}
	if err := store.UpsertAvailability("sys", "", time.Now()); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty updater: err = %v, want ErrInvalid", err)
	}
}

func TestInsertRunRejectsBadInput(t *testing.T) {
	store := newStore(t)
	if err := store.InsertRun(Run{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
	if err := store.InsertRun(Run{
		ID: "x", SystemID: "s", Kind: RunKind("bogus"),
		StartedAt: time.Now(),
	}); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestFinishRunMissing(t *testing.T) {
	store := newStore(t)
	if err := store.FinishRun("ghost", time.Now(), 0, 0, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestAcquireLockRejectsEmpty(t *testing.T) {
	store := newStore(t)
	if err := store.AcquireLock("", "r", time.Now()); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty system: err = %v, want ErrInvalid", err)
	}
}

func TestConflictingRunOnFreeSystem(t *testing.T) {
	store := newStore(t)
	got, err := store.ConflictingRun("nobody")
	if err != nil {
		t.Fatalf("ConflictingRun: %v", err)
	}
	if got != "" {
		t.Errorf("ConflictingRun = %q, want \"\"", got)
	}
}

func TestGetCustomNotFound(t *testing.T) {
	store := newStore(t)
	if _, err := store.GetCustom("custom.nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestListRunsCapsLimit(t *testing.T) {
	store := newStore(t)
	// Default limit applies when caller passes 0 or negative.
	if _, err := store.ListRuns("nobody", 0); err != nil {
		t.Errorf("ListRuns: %v", err)
	}
	if _, err := store.ListRuns("nobody", -1); err != nil {
		t.Errorf("ListRuns: %v", err)
	}
	if _, err := store.ListRuns("nobody", 99999); err != nil {
		t.Errorf("ListRuns: %v", err)
	}
}

func TestRegistryUpdateCustomDelegates(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)
	if _, err := reg.CreateCustom(sampleDef("custom.upd")); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	d := sampleDef("custom.upd")
	d.DisplayName = "after"
	got, err := reg.UpdateCustom(d)
	if err != nil {
		t.Fatalf("UpdateCustom: %v", err)
	}
	if got.DisplayName != "after" {
		t.Errorf("display_name = %q, want after", got.DisplayName)
	}
}

func TestRegistryDeleteCustomRejectsBadID(t *testing.T) {
	store := newStore(t)
	reg := NewRegistry(store)
	if err := reg.DeleteCustom("no-prefix", time.Now()); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}
