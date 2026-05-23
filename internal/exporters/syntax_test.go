// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeExec implements ansible.Executor for syntax-checker tests.
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
	err := chk.Check(context.Background(), []byte("not yaml"))
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
	chk := &AnsibleSyntaxChecker{Executor: &fakeExec{err: errors.New("missing")}}
	if err := chk.Check(context.Background(), []byte("x")); !errors.Is(err, ErrSyntax) {
		t.Errorf("err = %v, want ErrSyntax wrap", err)
	}
}

func TestTrimStderr(t *testing.T) {
	if got := trimStderr([]byte("short")); got != "short" {
		t.Errorf("short = %q", got)
	}
	long := strings.Repeat("x", 600)
	got := trimStderr([]byte(long))
	if len(got) == len(long) {
		t.Errorf("long stderr not trimmed: %d", len(got))
	}
}
