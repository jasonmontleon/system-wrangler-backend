// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuiltinParsingFixtures exercises each builtin's *_parse_test.yml
// fixture through real `ansible-playbook` so the same Jinja engine the
// runner uses validates the parse pipeline. The CLAUDE.md "shell out
// behind an injected executor" rule is intentionally relaxed here: the
// whole point is to catch Jinja-escape and filter-chain bugs that a
// fake executor would mask. Without ansible installed (e.g. lean CI
// runners) the test skips with a clear message.
//
// Add a fixture by dropping `<scope>_parse_test.yml` next to a
// builtin's `check.yml` / `apply.yml`; the fixture asserts on hard-
// coded `*.stdout_lines` inputs against expected outputs via
// `ansible.builtin.assert`. The Go test fails any non-zero exit.
func TestBuiltinParsingFixtures(t *testing.T) {
	ansiblePath, err := exec.LookPath("ansible-playbook")
	if err != nil {
		t.Skip("ansible-playbook not in PATH; install ansible to run parsing fixtures")
	}

	var fixtures []string
	if err := filepath.Walk("builtins", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), "_parse_test.yml") {
			fixtures = append(fixtures, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk builtins/: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no *_parse_test.yml fixtures discovered under builtins/")
	}

	for _, f := range fixtures {
		t.Run(strings.ReplaceAll(filepath.ToSlash(f), "/", "_"), func(t *testing.T) {
			// f comes from filepath.Walk over the hardcoded
			// "builtins" directory, so it's a repo-relative path
			// under our control — gosec G204 false positive.
			cmd := exec.Command(ansiblePath, //nolint:gosec
				"-i", "localhost,",
				"--connection=local",
				f,
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("playbook %q failed: %v\noutput:\n%s", f, err, out)
			}
		})
	}
}
