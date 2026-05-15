// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSpecParsesAsYAML pins the spec to "parses cleanly under a real
// YAML 1.2 parser." This catches the class of failure where an
// unquoted scalar starts a flow mapping (`summary: text {a: b}`),
// tabs sneak into indentation, anchors go bad, etc. — bugs the
// drift test's line scanner happily reads past but Redoc's
// js-yaml chokes on.
//
// We don't validate against the OpenAPI schema here; the goal is
// "is the bytestream parseable as YAML." Schema-shape drift is
// covered by the route enumeration test.
func TestSpecParsesAsYAML(t *testing.T) {
	var doc any
	if err := yaml.Unmarshal(Spec, &doc); err != nil {
		t.Fatalf("spec.yaml does not parse: %v", err)
	}
	if doc == nil {
		t.Fatal("spec.yaml parsed to nil — embed is empty?")
	}
}

// TestSpecHasOpenAPIRoot is a cheap structural sanity check: after
// parsing, the top-level must be a mapping with an `openapi` key.
// Catches a regression where the file got truncated to a comment or
// the embed pointed at the wrong path.
func TestSpecHasOpenAPIRoot(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(Spec, &doc); err != nil {
		t.Fatalf("spec.yaml does not parse: %v", err)
	}
	if _, ok := doc["openapi"]; !ok {
		t.Errorf("spec.yaml has no top-level `openapi:` key; got keys %v", keys(doc))
	}
	if _, ok := doc["paths"]; !ok {
		t.Errorf("spec.yaml has no top-level `paths:` key; got keys %v", keys(doc))
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
