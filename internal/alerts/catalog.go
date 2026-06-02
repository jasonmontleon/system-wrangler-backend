// SPDX-License-Identifier: Apache-2.0

package alerts

// Metric is a curated catalog key. Each maps to a per-system PromQL
// expression — a vector whose samples each carry a system_id label, so
// the evaluator can read one value per system. The expressions are the
// fleet-wide (empty-id) forms of the helpers in the frontend's
// src/api/promql.ts, kept byte-for-byte equivalent so an alert on
// "memory > 90%" trips on exactly the value the memory chart draws.
//
// load1 and swap_used_pct are Linux/BSD only (node_* with no Windows
// equivalent); on Windows hosts those series are absent and the rule
// simply never matches them — the same accepted telemetry gap the
// charts have.
type Metric string

// Catalog metric keys.
const (
	MetricMemUsedPct  Metric = "mem_used_pct"
	MetricFSUsedPct   Metric = "fs_used_pct"
	MetricCPUBusyPct  Metric = "cpu_busy_pct"
	MetricSwapUsedPct Metric = "swap_used_pct"
	MetricLoad1       Metric = "load1"
)

// CatalogEntry describes one curated metric for the rule editor.
type CatalogEntry struct {
	Metric Metric `json:"metric"`
	Label  string `json:"label"`
	Unit   string `json:"unit"`
	Expr   string `json:"-"`
}

// Filter clauses mirror src/api/promql.ts so the catalog excludes the
// same pseudo-filesystems the charts do.
const (
	fsFilterNode    = `fstype!~"tmpfs|devtmpfs|squashfs|overlay|ramfs|nsfs|cgroup.*|tracefs|debugfs|fusectl|sysfs|proc|pstore|bpf|configfs|securityfs|hugetlbfs|mqueue|autofs|binfmt_misc",mountpoint!~"/System/Library/.*|/Library/Developer/CoreSimulator/Volumes/.*|/System/Volumes/(Hardware|xarts|iSCPreboot|Preboot|Update|VM).*|/private/tmp/tmp-mount-.*"`
	fsFilterWindows = `volume!~"HarddiskVolume.*"`
	cpuRange        = "5m"
)

// Expressions are the empty-id forms from promql.ts. Each yields a
// vector keyed by system_id.
const (
	exprMemUsedPct = `(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 ` +
		`or ((node_memory_active_bytes + node_memory_wired_bytes) / ` +
		`(node_memory_active_bytes + node_memory_inactive_bytes + ` +
		`node_memory_wired_bytes + node_memory_free_bytes)) * 100 ` +
		`or (1 - windows_memory_available_bytes / windows_memory_physical_total_bytes) * 100 ` +
		`or (1 - windows_os_physical_memory_free_bytes / windows_os_visible_memory_bytes) * 100`

	exprCPUBusyPct = `100 - (avg by (system_id)(rate(node_cpu_seconds_total{mode="idle"}[` + cpuRange + `])) * 100) ` +
		`or 100 - (avg by (system_id)(rate(windows_cpu_time_total{mode="idle"}[` + cpuRange + `])) * 100)`

	exprFSUsedPct = `max by (system_id)((1 - node_filesystem_avail_bytes{` + fsFilterNode + `} / node_filesystem_size_bytes{` + fsFilterNode + `}) * 100) ` +
		`or max by (system_id)((1 - windows_logical_disk_free_bytes{` + fsFilterWindows + `} / windows_logical_disk_size_bytes{` + fsFilterWindows + `}) * 100)`

	exprSwapUsedPct = `(node_memory_SwapTotal_bytes - node_memory_SwapFree_bytes) / node_memory_SwapTotal_bytes * 100`

	exprLoad1 = `node_load1`
)

// catalog is the source of truth for curated metrics.
var catalog = map[Metric]CatalogEntry{
	MetricMemUsedPct:  {Metric: MetricMemUsedPct, Label: "Memory Used", Unit: "%", Expr: exprMemUsedPct},
	MetricFSUsedPct:   {Metric: MetricFSUsedPct, Label: "Worst Filesystem Used", Unit: "%", Expr: exprFSUsedPct},
	MetricCPUBusyPct:  {Metric: MetricCPUBusyPct, Label: "CPU Busy", Unit: "%", Expr: exprCPUBusyPct},
	MetricSwapUsedPct: {Metric: MetricSwapUsedPct, Label: "Swap Used", Unit: "%", Expr: exprSwapUsedPct},
	MetricLoad1:       {Metric: MetricLoad1, Label: "Load (1m)", Unit: "", Expr: exprLoad1},
}

// catalogOrder pins the display order for the editor; map iteration is
// unstable so the handler walks this slice instead.
var catalogOrder = []Metric{
	MetricMemUsedPct, MetricFSUsedPct, MetricCPUBusyPct, MetricSwapUsedPct, MetricLoad1,
}

// IsValid reports whether m is a known catalog metric.
func (m Metric) IsValid() bool {
	_, ok := catalog[m]
	return ok
}

// Expr returns the per-system PromQL for m, or "" if m is unknown.
func (m Metric) Expr() string {
	return catalog[m].Expr
}

// CatalogEntries returns the curated metrics in display order, for the
// rule editor to populate its metric dropdown.
func CatalogEntries() []CatalogEntry {
	out := make([]CatalogEntry, 0, len(catalogOrder))
	for _, m := range catalogOrder {
		out = append(out, catalog[m])
	}
	return out
}
