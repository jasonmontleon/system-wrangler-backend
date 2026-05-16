// SPDX-License-Identifier: Apache-2.0

package ansible

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// Executor is the seam between Runner and the real binaries it
// invokes (ansible-playbook, ssh-keyscan). Tests inject a fake to
// avoid spawning processes; production wires in ExecExecutor.
//
// Run returns (stdout, stderr, exitCode, err). err is non-nil only
// for failures the OS surfaces (binary not on PATH, signal-caused
// termination, context cancelled). A normal non-zero exit is
// reported via exitCode with err == nil — callers check exitCode to
// distinguish success from "ansible reported a task failure."
type Executor interface {
	Run(ctx context.Context, cmd string, args []string, env []string, stdin []byte) (stdout, stderr []byte, exitCode int, err error)
}

// ExecExecutor is the production Executor. It shells out via
// os/exec.CommandContext so context cancellation reliably kills the
// child process and any sub-tree (Setpgid would be neater but
// crosses platform boundaries; CommandContext is good enough for
// the container's Linux base).
type ExecExecutor struct{}

// Run satisfies Executor by spawning cmd with the given args and
// env. stdin, when non-nil, is piped to the child.
func (ExecExecutor) Run(ctx context.Context, cmd string, args []string, env []string, stdin []byte) ([]byte, []byte, int, error) {
	// gosec G204: cmd is hard-coded by callers to "ansible-playbook"
	// or "ssh-keyscan" — never operator input. The flag-and-positional
	// arguments contain operator-controlled paths (the synthesized
	// inventory, temp key files, the playbook path), all of which we
	// generated ourselves in os.MkdirTemp.
	c := exec.CommandContext(ctx, cmd, args...) //nolint:gosec
	if len(env) > 0 {
		c.Env = env
	}
	if len(stdin) > 0 {
		c.Stdin = bytes.NewReader(stdin)
	}
	var outBuf, errBuf bytes.Buffer
	c.Stdout = &outBuf
	c.Stderr = &errBuf
	err := c.Run()
	exit := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// Non-zero exit: surface code, hide err so the caller's
			// happy-path branch ("ansible reported a failure") is
			// not also taking the OS-error branch.
			return outBuf.Bytes(), errBuf.Bytes(), ee.ExitCode(), nil
		}
		// Anything else (binary missing, signal, ctx cancelled) IS
		// an OS-level error worth surfacing.
		return outBuf.Bytes(), errBuf.Bytes(), -1, fmt.Errorf("ansible: exec %s: %w", cmd, err)
	}
	return outBuf.Bytes(), errBuf.Bytes(), exit, nil
}
