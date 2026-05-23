// SPDX-License-Identifier: Apache-2.0

package exporters

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
// YAML. AnsibleSyntaxChecker is the production implementation; tests
// inject a stub.
type SyntaxChecker interface {
	Check(ctx context.Context, body []byte) error
}

// AnsibleSyntaxChecker runs `ansible-playbook --syntax-check` against
// a temp copy of the body. Mirrors updaters.AnsibleSyntaxChecker; the
// guard logic is identical, the wrapper exists so each substrate can
// own its own error-class namespace without cross-importing.
type AnsibleSyntaxChecker struct {
	Executor ansible.Executor
}

// ErrSyntax wraps a syntax-check failure. The error message carries
// the relevant stderr; handlers surface it as 400 to the caller.
var ErrSyntax = errors.New("exporters: syntax check failed")

// Check satisfies SyntaxChecker.
func (a *AnsibleSyntaxChecker) Check(ctx context.Context, body []byte) error {
	if a.Executor == nil {
		return fmt.Errorf("%w: executor not configured", ErrInvalid)
	}
	dir, err := os.MkdirTemp("", "sw-exporter-syntax-")
	if err != nil {
		return fmt.Errorf("exporters: mkdir tmp: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			slog.Warn("exporters: syntax tmp cleanup", "err", rmErr, "dir", dir)
		}
	}()
	path := filepath.Join(dir, "playbook.yml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("exporters: write playbook: %w", err)
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

func trimStderr(b []byte) string {
	const maxBytes = 512
	s := string(b)
	if len(s) > maxBytes {
		s = s[:maxBytes] + "…"
	}
	return s
}

// credentialPattern matches a YAML key that looks like the operator
// embedded a credential directly in the playbook. Conservative on
// purpose — false positives are recoverable (rename the field).
var credentialPattern = regexp.MustCompile(`(?im)^[ \t]*(password|token|secret)[ \t]*:`)

// ErrInlineCredential reports that the playbook trips the heuristic.
var ErrInlineCredential = errors.New("exporters: playbook appears to inline a credential")

// scanInlineCredentials returns nil when the body passes; otherwise
// ErrInlineCredential wrapped with the line number and matched key.
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
