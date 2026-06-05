// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/prometheus/promql/parser"
)

func TestEnforceSystemIDInjectsMatcher(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		allowed []string
		// wantAll are substrings that must all appear in the output.
		wantAll []string
	}{
		{
			name:    "bare selector single id uses equality",
			query:   `up`,
			allowed: []string{"sys-a"},
			wantAll: []string{`system_id="sys-a"`},
		},
		{
			name:    "bare selector multiple ids uses regex",
			query:   `up`,
			allowed: []string{"sys-a", "sys-b"},
			wantAll: []string{`system_id=~"sys-a|sys-b"`},
		},
		{
			name:    "every branch of an or chain is constrained",
			query:   `node_cpu_seconds_total or windows_cpu_time_total`,
			allowed: []string{"sys-a"},
			wantAll: []string{`node_cpu_seconds_total{system_id="sys-a"}`, `windows_cpu_time_total{system_id="sys-a"}`},
		},
		{
			name:    "matrix selector inside rate is constrained",
			query:   `rate(node_network_receive_bytes_total[5m])`,
			allowed: []string{"sys-a"},
			wantAll: []string{`node_network_receive_bytes_total{system_id="sys-a"}`},
		},
		{
			name:    "label_replace cannot widen the read set",
			query:   `label_replace(avg(node_memory_MemAvailable_bytes), "x", "y", "", "")`,
			allowed: []string{"sys-a"},
			wantAll: []string{`node_memory_MemAvailable_bytes{system_id="sys-a"}`},
		},
		{
			name:    "caller's own matcher is preserved and intersected",
			query:   `up{system_id="sys-z"}`,
			allowed: []string{"sys-a", "sys-b"},
			wantAll: []string{`system_id="sys-z"`, `system_id=~"sys-a|sys-b"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := enforceSystemID(tc.query, tc.allowed)
			if err != nil {
				t.Fatalf("enforceSystemID(%q): %v", tc.query, err)
			}
			for _, want := range tc.wantAll {
				if !strings.Contains(out, want) {
					t.Errorf("output %q missing %q", out, want)
				}
			}
			// The rewritten query must still parse.
			if _, err := parser.NewParser(parser.Options{}).ParseExpr(out); err != nil {
				t.Errorf("rewritten query does not parse: %q: %v", out, err)
			}
		})
	}
}

func TestEnforceSystemIDRejectsInvalidQuery(t *testing.T) {
	if _, err := enforceSystemID("up{{{", []string{"sys-a"}); err == nil {
		t.Error("expected a parse error for malformed query")
	}
}

func TestSystemIDMatcherEscapesRegexMetacharacters(t *testing.T) {
	// A value with regex metacharacters must be escaped so it can't
	// broaden the match.
	m, err := systemIDMatcher([]string{"a.b", "c+d"})
	if err != nil {
		t.Fatalf("systemIDMatcher: %v", err)
	}
	// The literal dotted/plus ids must match; a string that the
	// unescaped regex would have matched must not.
	if !m.Matches("a.b") {
		t.Errorf("matcher should match the literal id a.b")
	}
	if m.Matches("axb") {
		t.Errorf("matcher matched axb — '.' was not escaped")
	}
}

func TestSystemIDMatcherEmptyNeverMatches(t *testing.T) {
	m, err := systemIDMatcher(nil)
	if err != nil {
		t.Fatalf("systemIDMatcher(nil): %v", err)
	}
	for _, v := range []string{"", "sys-a", "anything"} {
		if m.Matches(v) {
			t.Errorf("empty-allowed matcher should never match, but matched %q", v)
		}
	}
}
