// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"errors"
	"testing"
	"time"

	"system-wrangler-backend/internal/ansible"
)

func TestCombineOutput(t *testing.T) {
	cases := []struct {
		name           string
		stdout, stderr string
		want           string
	}{
		{"both empty", "", "", ""},
		{"stdout only", "hello\n", "", "hello\n"},
		{"stderr only", "", "boom", "boom"},
		{"both", "hello", "boom", "hello\n--- stderr ---\nboom"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := combineOutput([]byte(tt.stdout), []byte(tt.stderr))
			if got != tt.want {
				t.Errorf("combineOutput = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSortedKeys(t *testing.T) {
	in := map[string]bool{"c": true, "a": true, "b": true}
	out := sortedKeys(in)
	want := []string{"a", "b", "c"}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("sortedKeys[%d] = %q, want %q", i, out[i], want[i])
		}
	}
	if got := sortedKeys(map[string]bool{}); len(got) != 0 {
		t.Errorf("sortedKeys(empty) returned %d entries, want 0", len(got))
	}
}

func TestAuditActions(t *testing.T) {
	cases := []struct {
		k          RunKind
		wantStart  string
		wantFinish string
	}{
		{RunKindCheck, "system.update.check.start", "system.update.check.complete"},
		{RunKindApply, "system.update.apply.start", "system.update.apply.complete"},
		{RunKindInspect, "system.inspect.start", "system.inspect.complete"},
		{RunKind("bogus"), "system.inspect.start", "system.inspect.complete"},
	}
	for _, tt := range cases {
		gs, gc := auditActions(tt.k)
		if gs != tt.wantStart || gc != tt.wantFinish {
			t.Errorf("auditActions(%q) = (%q, %q), want (%q, %q)",
				tt.k, gs, gc, tt.wantStart, tt.wantFinish)
		}
	}
}

func TestRunnerNowAndNewIDFallback(t *testing.T) {
	r := &Runner{}
	if r.now().IsZero() {
		t.Errorf("now() returned zero")
	}
	if id := r.newID(); len(id) != 36 {
		t.Errorf("newID() = %q (len %d), want a 36-char uuid", id, len(id))
	}
}

func TestRunnerNowOverride(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := &Runner{Now: func() time.Time { return fixed }}
	if !r.now().Equal(fixed) {
		t.Errorf("now() = %v, want %v", r.now(), fixed)
	}
	r.NewID = func() string { return "fixed-id" }
	if r.newID() != "fixed-id" {
		t.Errorf("newID() override not honored")
	}
}

func TestRegistryNoUpdaters(t *testing.T) {
	// An empty registry (no builtins, no custom) makes Inspect bail
	// before composing a playbook. Build one ad hoc to exercise that
	// guard without disturbing the package-level Builtins() list.
	store := newStore(t)
	reg := &Registry{store: store, builtins: map[string]Definition{}}
	f := newRunnerFixture(t)
	f.runner.Registry = reg
	if _, err := f.runner.Inspect(context.Background(), f.systemID); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestApplyConflictDoesNotCallAnsible(t *testing.T) {
	// Mirrors the Apply conflict test but for Check, exercising the
	// same conflict branch through runUpdater.
	f := newRunnerFixture(t)
	if err := f.store.AcquireLock(f.systemID, "outside", time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := f.runner.Check(context.Background(), f.systemID, "builtin.dnf"); !errors.Is(err, ErrConflict) {
		t.Errorf("err = %v, want ErrConflict", err)
	}
	if len(f.ansible.calls) != 0 {
		t.Errorf("ansible was invoked: %+v", f.ansible.calls)
	}
}

func TestInspectAnsibleErrorPath(t *testing.T) {
	f := newRunnerFixture(t)
	f.queue(ansible.Run{Status: ansible.RunFailure, ExitCode: -1}, errors.New("exec died"))
	res, err := f.runner.Inspect(context.Background(), f.systemID)
	if err == nil {
		t.Fatalf("err = nil, want propagated")
	}
	if res.Status != ansible.RunFailure {
		t.Errorf("status = %q, want failure", res.Status)
	}
	rows := auditRowsWithAction(t, f.auditStore, "system.inspect.complete")
	if len(rows) != 1 {
		t.Fatalf("complete rows = %d", len(rows))
	}
}
