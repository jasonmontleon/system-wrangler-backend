// SPDX-License-Identifier: Apache-2.0

package ansible

import (
	"context"
	"strings"
	"testing"
)

func TestExecExecutorCapturesStdout(t *testing.T) {
	ex := ExecExecutor{}
	stdout, _, exit, err := ex.Run(context.Background(), "/bin/sh", []string{"-c", "echo hello"}, nil, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exit != 0 {
		t.Errorf("exit = %d, want 0", exit)
	}
	if !strings.Contains(string(stdout), "hello") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestExecExecutorNonZeroExit(t *testing.T) {
	ex := ExecExecutor{}
	_, _, exit, err := ex.Run(context.Background(), "/bin/sh", []string{"-c", "exit 7"}, nil, nil)
	if err != nil {
		t.Fatalf("OS error on non-zero exit: %v", err)
	}
	if exit != 7 {
		t.Errorf("exit = %d, want 7", exit)
	}
}

func TestExecExecutorMissingBinaryReturnsOSError(t *testing.T) {
	ex := ExecExecutor{}
	_, _, exit, err := ex.Run(context.Background(), "/no/such/binary/sw-test", nil, nil, nil)
	if err == nil {
		t.Fatal("expected an OS error for missing binary")
	}
	if exit != -1 {
		t.Errorf("exit = %d, want -1 on OS error", exit)
	}
}

func TestExecExecutorRespectsContextCancellation(t *testing.T) {
	ex := ExecExecutor{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err := ex.Run(ctx, "/bin/sh", []string{"-c", "sleep 5"}, nil, nil)
	if err == nil {
		t.Error("expected an error from cancelled context")
	}
}
