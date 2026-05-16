// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeExec implements ansible.Executor for syntax-checker tests.
// stdout/stderr/exit/err are returned verbatim.
type fakeExec struct {
	stdout, stderr []byte
	exit           int
	err            error
	called         bool
}

func (f *fakeExec) Run(_ context.Context, _ string, _ []string, _ []string, _ []byte) ([]byte, []byte, int, error) {
	f.called = true
	return f.stdout, f.stderr, f.exit, f.err
}

func TestSyntaxCheckerOK(t *testing.T) {
	chk := &AnsibleSyntaxChecker{Executor: &fakeExec{exit: 0}}
	if err := chk.Check(context.Background(), []byte("- hosts: all\n")); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestSyntaxCheckerNonZeroExit(t *testing.T) {
	chk := &AnsibleSyntaxChecker{Executor: &fakeExec{
		exit:   4,
		stderr: []byte("ERROR! mapping values are not allowed at line 3\n"),
	}}
	err := chk.Check(context.Background(), []byte("not yaml at all"))
	if !errors.Is(err, ErrSyntax) {
		t.Fatalf("err = %v, want ErrSyntax", err)
	}
}

func TestSyntaxCheckerExecutorMissing(t *testing.T) {
	chk := &AnsibleSyntaxChecker{}
	if err := chk.Check(context.Background(), []byte("x")); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v, want ErrInvalid", err)
	}
}

func TestSyntaxCheckerExecutorError(t *testing.T) {
	chk := &AnsibleSyntaxChecker{Executor: &fakeExec{err: errors.New("binary missing")}}
	if err := chk.Check(context.Background(), []byte("x")); !errors.Is(err, ErrSyntax) {
		t.Errorf("err = %v, want ErrSyntax-wrapped", err)
	}
}

func TestTrimStderr(t *testing.T) {
	short := []byte("short")
	if got := trimStderr(short); got != "short" {
		t.Errorf("short = %q, want %q", got, "short")
	}
	long := make([]byte, 1000)
	for i := range long {
		long[i] = 'a'
	}
	got := trimStderr(long)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("long output should end with ellipsis: %q", got)
	}
}
