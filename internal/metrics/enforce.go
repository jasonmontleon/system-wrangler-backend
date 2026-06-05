// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

// systemIDLabel is the per-series label every exporter carries identifying
// the System Wrangler system the metric belongs to. Scope enforcement
// pins queries to the caller's visible set of these.
const systemIDLabel = "system_id"

// promParser holds only immutable options, so a single instance is reused
// across requests; ParseExpr spins up a fresh internal parser per call and
// is safe for concurrent use.
var promParser = parser.NewParser(parser.Options{})

// enforceSystemID parses a PromQL expression and AND-appends a system_id
// matcher — constrained to allowed — onto every vector/matrix selector in
// the query, so the rewritten query can only ever read series for systems
// the caller is permitted to see.
//
// AND-appending (rather than replacing) is what makes this sound: PromQL
// requires every matcher on a selector to hold, so a caller's own
// `system_id="x"` simply intersects with our ceiling (matching nothing if
// x is outside allowed, and preserving a legitimate single-system filter
// when x is inside it). A caller cannot widen the set with a regex, a
// negative matcher, or a label_replace, because all of those are evaluated
// against series already filtered by the injected matcher. Matrix and
// subquery selectors wrap a VectorSelector, which Inspect visits, so they
// are covered by the single VectorSelector case.
//
// allowed must be non-empty; the caller short-circuits the zero-visibility
// case without a query rather than relying on a never-match matcher.
func enforceSystemID(query string, allowed []string) (string, error) {
	expr, err := promParser.ParseExpr(query)
	if err != nil {
		return "", fmt.Errorf("metrics: parse query: %w", err)
	}
	m, err := systemIDMatcher(allowed)
	if err != nil {
		return "", err
	}
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		if vs, ok := node.(*parser.VectorSelector); ok {
			vs.LabelMatchers = append(vs.LabelMatchers, m)
		}
		return nil
	})
	return expr.String(), nil
}

// systemIDMatcher builds the label matcher constraining system_id to
// allowed. A single id becomes an exact match; multiple ids become an
// (anchored) regex alternation. Each id is regex-escaped so a value
// containing regex metacharacters can't broaden the match — System
// Wrangler ids are UUIDs today, but escaping keeps the guarantee
// independent of the id format.
func systemIDMatcher(allowed []string) (*labels.Matcher, error) {
	if len(allowed) == 0 {
		// Defensive: a never-match matcher. Prometheus anchors regex
		// matchers as ^(?:VALUE)$, and "." after the end anchor can
		// never be satisfied. The handler is expected to short-circuit
		// before reaching here.
		return labels.NewMatcher(labels.MatchRegexp, systemIDLabel, ".^")
	}
	if len(allowed) == 1 {
		return labels.NewMatcher(labels.MatchEqual, systemIDLabel, allowed[0])
	}
	escaped := make([]string, len(allowed))
	for i, id := range allowed {
		escaped[i] = regexp.QuoteMeta(id)
	}
	return labels.NewMatcher(labels.MatchRegexp, systemIDLabel, strings.Join(escaped, "|"))
}
