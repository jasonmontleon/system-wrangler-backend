// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// detectMarker is the line each per-updater task in the composed
// inspection playbook prints when the binary is found on the target.
// The runner greps the ansible stdout for these to translate
// playbook output into system_updaters rows. Format: marker, single
// space, updater id (already constrained by definition validation /
// the builtin/custom prefix rule, so no quoting needed).
const detectMarker = "SW_DETECTED:"

// affectedMarker is the line check / apply playbooks emit to surface
// "this many things would change" (check) or "this many things
// changed" (apply). The runner extracts the integer and stuffs it
// into audit detail. Playbooks that don't emit a marker get 0 in
// detail — accurate for "did nothing" or "didn't report"; the run
// row's exit_code is the source of truth for success/failure.
const affectedMarker = "SW_AFFECTED_COUNT:"

// pendingPackageMarker is one line per pending package emitted by
// check playbooks via a debug task. The payload format is
// `<name>|<old>|<new>` — pipe-delimited so each marker carries the
// installed and available versions. Either version may be empty
// when the package manager can't surface it cheaply (flatpak,
// snap). For backward compatibility a payload with no pipe is
// treated as a bare name with both versions empty. Apply playbooks
// do not emit the marker — the column always reflects the most
// recent check.
const pendingPackageMarker = "SW_PENDING_PACKAGE:"

// inspectionPlaybook composes a one-shot playbook that probes the
// target system for every registered updater's DetectBinary. Each
// updater contributes three tasks gated on the `sw_is_windows`
// inventory var the runner writes per host: a Unix probe
// (ansible.builtin.shell + `command -v`), a Windows probe
// (ansible.windows.win_command + `where.exe`), and an emit task that
// ORs the two registered rcs with `default(1)`.
//
// Facts are NOT gathered: the legacy setup module crashes over
// OpenSSH-on-Windows (`Parameter format not correct - ;`) before
// ansible can decide which platform variant to use. Routing the
// branch through an inventory var the Go runner already knows
// sidesteps the chicken-and-egg.
//
// The composer trusts that defs have already passed Validate — that
// guarantees DetectBinary matches detectBinaryPattern and ID matches
// the builtin./custom. prefix rule, so no further escaping is
// required.
func inspectionPlaybook(defs []Definition) []byte {
	var b bytes.Buffer
	b.WriteString("- name: System Wrangler inspect\n")
	b.WriteString("  hosts: all\n")
	b.WriteString("  gather_facts: false\n")
	b.WriteString("  become: false\n")
	b.WriteString("  tasks:\n")
	for _, d := range defs {
		v := varName(d.ID)
		fmt.Fprintf(&b, "    - name: detect %s (unix)\n", d.ID)
		fmt.Fprintf(&b, "      ansible.builtin.shell: 'command -v %s'\n", d.DetectBinary)
		b.WriteString("      failed_when: false\n")
		b.WriteString("      changed_when: false\n")
		fmt.Fprintf(&b, "      register: %s\n", v)
		b.WriteString("      when: not (sw_is_windows | default(false) | bool)\n")
		fmt.Fprintf(&b, "    - name: detect %s (windows)\n", d.ID)
		fmt.Fprintf(&b, "      ansible.windows.win_command: 'where.exe %s'\n", d.DetectBinary)
		b.WriteString("      failed_when: false\n")
		b.WriteString("      changed_when: false\n")
		fmt.Fprintf(&b, "      register: %s_win\n", v)
		b.WriteString("      when: sw_is_windows | default(false) | bool\n")
		fmt.Fprintf(&b, "    - name: emit %s\n", d.ID)
		b.WriteString("      ansible.builtin.debug:\n")
		fmt.Fprintf(&b, "        msg: '%s %s'\n", detectMarker, d.ID)
		fmt.Fprintf(&b, "      when: (%s.rc | default(1)) == 0 or (%s_win.rc | default(1)) == 0\n", v, v)
	}
	return b.Bytes()
}

// varName turns an updater id into a valid ansible variable name —
// alpha-num + underscore. The id is already a safe charset
// (builtin./custom. plus the trailing slug), so a single character
// substitution covers it.
func varName(id string) string {
	r := strings.NewReplacer(".", "_", "-", "_")
	return "r_" + r.Replace(id)
}

// parseDetected returns the set of updater ids the inspection
// playbook reported as present. The ansible default callback's
// `debug` task output puts the `msg` value on its own line; we
// tolerate any whitespace around the marker so a future callback
// switch doesn't silently break detection.
func parseDetected(stdout []byte) map[string]bool {
	out := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	// Bump the buffer so a chatty ansible debug task (one large
	// fact dump on a line) doesn't truncate the marker we're
	// looking for.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, detectMarker)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(detectMarker):]
		// Default callback formats debug.msg as `"msg": "SW_DETECTED:
		// custom.alpha"` inside a larger JSON-ish block. Strip the
		// JSON terminators in either order with whitespace — the
		// updater id charset never includes any of these characters,
		// so the trim is safe.
		rest = strings.Trim(rest, " \t\r\n\",}")
		if rest != "" {
			out[rest] = true
		}
	}
	return out
}

// parsePendingPackages collects every SW_PENDING_PACKAGE marker
// from stdout, preserving the playbook's emission order and
// de-duplicating exact repeats (a chatty debug callback can dump
// the same line twice). Returns an empty slice when no marker is
// emitted — playbooks that don't surface package names produce an
// empty list, which the SPA handles as "count only, no detail."
//
// Payload is `<name>|<old>|<new>`. A payload with no pipe is the
// pre-versions emission shape and is accepted as a bare name.
// Trailing fields may be empty (e.g. `foo||1.2` when only the new
// version is available); extra trailing pipes are tolerated and
// ignored.
func parsePendingPackages(stdout []byte) []PendingPackage {
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	out := []PendingPackage{}
	seen := map[PendingPackage]bool{}
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, pendingPackageMarker)
		if idx < 0 {
			continue
		}
		rest := strings.Trim(line[idx+len(pendingPackageMarker):], " \t\r\n\",}")
		if rest == "" {
			continue
		}
		parts := strings.SplitN(rest, "|", 3)
		pkg := PendingPackage{Name: strings.TrimSpace(parts[0])}
		if len(parts) > 1 {
			pkg.OldVersion = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			pkg.NewVersion = strings.TrimSpace(parts[2])
		}
		if pkg.Name == "" || seen[pkg] {
			continue
		}
		seen[pkg] = true
		out = append(out, pkg)
	}
	return out
}

// parseAffectedCount extracts the first SW_AFFECTED_COUNT integer
// from stdout. Returns 0 if the marker is absent or the value isn't
// parseable — callers stuff the result into audit detail and treat
// "no marker" as "0 affected" rather than a runtime error.
func parseAffectedCount(stdout []byte) int {
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, affectedMarker)
		if idx < 0 {
			continue
		}
		rest := strings.Trim(line[idx+len(affectedMarker):], " \t\r\n\",}")
		// Take the leading integer; an ansible callback may append
		// quote characters or trailing whitespace.
		var n int
		for _, c := range rest {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	return 0
}
