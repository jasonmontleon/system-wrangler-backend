// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	"bufio"
	"bytes"
	"strings"
)

// SW_EXPORTER_PORT / SERVICE / STATE markers each playbook must emit
// at the end of a successful install / status run. Parsed by the
// runner into a SystemExporter row.
const (
	markerPort    = "SW_EXPORTER_PORT:"
	markerService = "SW_EXPORTER_SERVICE:"
	markerState   = "SW_EXPORTER_STATE:"
)

// MarkerResult is the structured form of the three SW_EXPORTER_*
// markers parsed out of a playbook's stdout. All three fields may be
// empty when the playbook didn't emit them (e.g. it failed before
// reaching the debug tasks); callers stuff what they got into the
// upsert and let the absent fields stay zeroed.
type MarkerResult struct {
	Port        int
	ServiceName string
	StateRaw    string
}

// State maps StateRaw onto a typed State, defaulting to StateFailed
// when the playbook emitted something unexpected. The "running"
// keyword is the only success path; "installed" downgrades to
// StateInstalled (the binary is there but the service hasn't been
// observed up yet); any other non-empty value becomes StateFailed.
// An empty StateRaw also resolves to StateFailed — if the playbook
// didn't reach its debug task something went wrong.
func (m MarkerResult) State() State {
	switch strings.ToLower(strings.TrimSpace(m.StateRaw)) {
	case "running":
		return StateRunning
	case "installed":
		return StateInstalled
	case "removed":
		return StateRemoved
	default:
		return StateFailed
	}
}

// ParseMarkers walks ansible stdout for the three SW_EXPORTER_*
// markers and returns whatever was emitted. Order of emission
// doesn't matter; the last of each kind wins so a playbook that
// re-emits after a corrective step still surfaces the final value.
func ParseMarkers(stdout []byte) MarkerResult {
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var out MarkerResult
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, markerPort); idx >= 0 {
			out.Port = parseTrailingInt(line[idx+len(markerPort):])
		}
		if idx := strings.Index(line, markerService); idx >= 0 {
			out.ServiceName = trimMarker(line[idx+len(markerService):])
		}
		if idx := strings.Index(line, markerState); idx >= 0 {
			out.StateRaw = trimMarker(line[idx+len(markerState):])
		}
	}
	return out
}

// trimMarker peels the ansible default-callback wrappers off a marker
// payload. The default callback renders debug.msg inside a JSON-ish
// block, so trailing `",}` and whitespace need to come off. The
// marker payloads (port, service name, state keyword) never include
// any of those characters, so the trim is safe.
func trimMarker(s string) string {
	return strings.Trim(s, " \t\r\n\",}")
}

// parseTrailingInt extracts the leading decimal integer from a
// trimmed marker payload. Returns 0 when the value is missing or
// unparseable; the caller treats 0 as "marker absent" via the empty
// MarkerResult check downstream.
func parseTrailingInt(s string) int {
	rest := trimMarker(s)
	n := 0
	for _, c := range rest {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
