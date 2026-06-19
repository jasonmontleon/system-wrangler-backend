// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestBuiltinPlaybooksParseAsYAML loads every shipped builtin check.yml /
// apply.yml through a real YAML parser. The playbooks are embedded as raw
// bytes (builtins.go) and never decoded by Go, so a structural YAML error —
// e.g. an unquoted conditional whose value contains a "colon-space" that the
// parser reads as a nested mapping — would otherwise ship undetected and only
// surface when ansible refuses to load the playbook on a target. This guard
// runs everywhere (no ansible required), unlike TestBuiltinParsingFixtures.
func TestBuiltinPlaybooksParseAsYAML(t *testing.T) {
	var playbooks []string
	if err := filepath.Walk("builtins", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		name := info.Name()
		if strings.HasSuffix(name, "_parse_test.yml") {
			return nil
		}
		if name == "check.yml" || name == "apply.yml" {
			playbooks = append(playbooks, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk builtins/: %v", err)
	}
	if len(playbooks) == 0 {
		t.Fatal("no builtin check.yml/apply.yml playbooks discovered under builtins/")
	}

	for _, p := range playbooks {
		t.Run(strings.ReplaceAll(filepath.ToSlash(p), "/", "_"), func(t *testing.T) {
			// p comes from filepath.Walk over the hardcoded
			// "builtins" directory, so it's a repo-relative path
			// under our control — gosec G304 false positive.
			b, err := os.ReadFile(p) //nolint:gosec
			if err != nil {
				t.Fatalf("read %q: %v", p, err)
			}
			var doc any
			if err := yaml.Unmarshal(b, &doc); err != nil {
				t.Fatalf("playbook %q is not valid YAML: %v", p, err)
			}
		})
	}
}
