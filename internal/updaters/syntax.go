// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"

	"system-wrangler-backend/internal/ansible"
)

// SyntaxChecker validates that a playbook body is well-formed ansible
// YAML. The production implementation runs
// `ansible-playbook --syntax-check`; tests inject a stub.
type SyntaxChecker interface {
	Check(ctx context.Context, body []byte) error
}

// AnsibleSyntaxChecker runs ansible-playbook --syntax-check against
// a temp copy of the body. Errors carry the stderr text so the
// handler can surface the offending line back to the operator.
type AnsibleSyntaxChecker struct {
	Executor ansible.Executor
}

// ErrSyntax wraps a syntax-check failure. The error message carries
// the relevant stderr; handlers surface it as 400 to the caller.
var ErrSyntax = errors.New("updaters: syntax check failed")

// Check satisfies SyntaxChecker. It writes the body to a temp file
// and invokes `ansible-playbook --syntax-check -i localhost, <path>`
// against the runtime ansible binary. The inline `-i localhost,`
// makes ansible-playbook treat the run as a dry-parse against a
// single-host inventory — it never connects anywhere.
func (a *AnsibleSyntaxChecker) Check(ctx context.Context, body []byte) error {
	if a.Executor == nil {
		return fmt.Errorf("%w: executor not configured", ErrInvalid)
	}
	dir, err := os.MkdirTemp("", "sw-updater-syntax-")
	if err != nil {
		return fmt.Errorf("updaters: mkdir tmp: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("updaters: syntax tmp cleanup", "err", rmErr, "dir", dir)
		}
	}()
	path := filepath.Join(dir, "playbook.yml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("updaters: write playbook: %w", err)
	}
	args := []string{"--syntax-check", "-i", "localhost,", path}
	_, stderr, exit, runErr := a.Executor.Run(ctx, ansible.AnsiblePlaybookBinary, args, nil, nil)
	if runErr != nil {
		return fmt.Errorf("%w: %v", ErrSyntax, runErr)
	}
	if exit != 0 {
		return fmt.Errorf("%w: %s", ErrSyntax, trimStderr(stderr))
	}
	return nil
}

// trimStderr clips ansible's stderr to something a 400 response can
// reasonably surface without flooding the client. The first line is
// usually enough.
func trimStderr(b []byte) string {
	const maxBytes = 512
	s := string(b)
	if len(s) > maxBytes {
		s = s[:maxBytes] + "…"
	}
	return s
}

// credentialPattern matches a YAML key that looks like the operator
// embedded a credential directly in the playbook. Triggers on
// `password:`, `token:`, `secret:` at the start of a line (after
// optional indentation). The check is deliberately conservative —
// false positives are recoverable (rename the field) and the real
// authority is the ansible-auth substrate.
var credentialPattern = regexp.MustCompile(`(?im)^[ \t]*(password|token|secret)[ \t]*:`)

// ErrInlineCredential reports that the playbook body trips the
// credential heuristic.
var ErrInlineCredential = errors.New("updaters: playbook appears to inline a credential")

// scanInlineCredentials returns nil when the body passes; otherwise
// ErrInlineCredential wrapped with the line number and matched key
// so the handler can show the operator exactly what to fix.
func scanInlineCredentials(body []byte) error {
	idx := credentialPattern.FindIndex(body)
	if idx == nil {
		return nil
	}
	line := 1
	for i := 0; i < idx[0]; i++ {
		if body[i] == '\n' {
			line++
		}
	}
	match := string(body[idx[0]:idx[1]])
	return fmt.Errorf("%w: line %d: %q", ErrInlineCredential, line, match)
}
