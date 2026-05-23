// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"errors"
	"testing"
)

func TestCombineOutput(t *testing.T) {
	if got := combineOutput([]byte("a"), nil); got != "a" {
		t.Errorf("stdout only = %q", got)
	}
	if got := combineOutput(nil, []byte("err")); got != "err" {
		t.Errorf("stderr only = %q", got)
	}
	got := combineOutput([]byte("out"), []byte("err"))
	if got != "out\n--- stderr ---\nerr" {
		t.Errorf("combined = %q", got)
	}
}

func TestIsConflictFalsePositiveSafe(t *testing.T) {
	if isConflict(nil) {
		t.Errorf("nil is not a conflict")
	}
	if isConflict(errors.New("totally unrelated")) {
		t.Errorf("unrelated err must not match")
	}
	if !isConflict(errors.New("another run is in progress for x")) {
		t.Errorf("phrase-based conflict missed")
	}
	if !isConflict(ErrConflict) {
		t.Errorf("local ErrConflict not recognised")
	}
}

func TestConflictFromLockerPassthrough(t *testing.T) {
	if got := conflictFromLocker(nil); got != nil {
		t.Errorf("nil → %v", got)
	}
	if got := conflictFromLocker(errors.New("anything")); got != nil {
		t.Errorf("non-conflict → %v, want nil", got)
	}
	e := errors.New("another run is in progress")
	if got := conflictFromLocker(e); got != e {
		t.Errorf("passthrough mismatch")
	}
}

func TestAuditActionsMapping(t *testing.T) {
	cases := map[RunKind][2]string{
		RunKindInstall: {"system.exporter.install.start", "system.exporter.install.complete"},
		RunKindStatus:  {"system.exporter.status.start", "system.exporter.status.complete"},
		RunKindRemove:  {"system.exporter.remove.start", "system.exporter.remove.complete"},
	}
	for k, want := range cases {
		start, complete := auditActions(k)
		if start != want[0] || complete != want[1] {
			t.Errorf("%s → (%q, %q), want (%q, %q)", k, start, complete, want[0], want[1])
		}
	}
}

func TestNormalizeCustomID(t *testing.T) {
	if got := normalizeCustomID(""); got != "" {
		t.Errorf("empty → %q", got)
	}
	if got := normalizeCustomID("  foo  "); got != "custom.foo" {
		t.Errorf("bare slug = %q", got)
	}
	if got := normalizeCustomID("custom.bar"); got != "custom.bar" {
		t.Errorf("already-prefixed = %q", got)
	}
	if got := normalizeCustomID("builtin.evil"); got != "builtin.evil" {
		t.Errorf("builtin passes through unchanged for downstream rejection: %q", got)
	}
}
