// SPDX-License-Identifier: Apache-2.0

package alerts

import (
	"strings"
	"testing"
)

func TestCatalogEntriesAllValid(t *testing.T) {
	entries := CatalogEntries()
	if len(entries) != len(catalog) {
		t.Fatalf("CatalogEntries returned %d, catalog has %d", len(entries), len(catalog))
	}
	for _, e := range entries {
		if !e.Metric.IsValid() {
			t.Errorf("entry metric %q not valid", e.Metric)
		}
		if e.Label == "" {
			t.Errorf("metric %q has empty label", e.Metric)
		}
		if e.Expr == "" {
			t.Errorf("metric %q has empty expr", e.Metric)
		}
		if e.Expr != e.Metric.Expr() {
			t.Errorf("metric %q: CatalogEntries expr != Metric.Expr()", e.Metric)
		}
	}
}

func TestPerSystemMetricsCarrySystemID(t *testing.T) {
	// The aggregating metrics must group by system_id so the querier
	// gets one value per system. The non-aggregating ones (mem/swap/load)
	// inherit system_id from the underlying series, so they are exempt.
	for _, m := range []Metric{MetricCPUBusyPct, MetricFSUsedPct} {
		if !strings.Contains(m.Expr(), "by (system_id)") {
			t.Errorf("metric %q expr should aggregate by (system_id): %s", m, m.Expr())
		}
	}
}

func TestUnknownMetric(t *testing.T) {
	if Metric("nope").IsValid() {
		t.Error("unknown metric should be invalid")
	}
	if Metric("nope").Expr() != "" {
		t.Error("unknown metric Expr() should be empty")
	}
}
