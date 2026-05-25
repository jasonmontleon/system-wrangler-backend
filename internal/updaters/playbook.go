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

// osFamilyMarker / osDistributionMarker / virtualizationMarker are
// the platform-detection markers the inspect playbook emits per host.
// Format:
//
//	SW_OS_FAMILY: <Linux|Darwin|FreeBSD|OpenBSD|NetBSD|Windows>
//	SW_OS_DISTRIBUTION: <distribution>|<version>
//	SW_VIRTUALIZATION: <type>|<role>
//
// The runner persists the parsed values on hosts so the SPA can show
// an OS icon next to each row and an OS / Hardware pair on the
// detail page. Empty type with role!=guest = bare-metal.
const (
	osFamilyMarker       = "SW_OS_FAMILY:"
	osDistributionMarker = "SW_OS_DISTRIBUTION:"
	virtualizationMarker = "SW_VIRTUALIZATION:"
)

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
	writePlatformDetectTasks(&b)
	for _, d := range defs {
		v := varName(d.ID)
		fmt.Fprintf(&b, "    - name: detect %s (unix)\n", d.ID)
		fmt.Fprintf(&b, "      ansible.builtin.shell: 'command -v %s'\n", d.DetectBinary)
		b.WriteString("      failed_when: false\n")
		b.WriteString("      changed_when: false\n")
		fmt.Fprintf(&b, "      register: %s\n", v)
		b.WriteString("      when: not (sw_is_windows | default(false) | bool)\n")
		b.WriteString("      environment:\n")
		b.WriteString("        PATH: '/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin'\n")
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

// writePlatformDetectTasks emits the gather_subset + win_shell pair
// the inspect playbook uses to surface OS family / distribution /
// virtualization markers. Unix hosts run `ansible.builtin.setup` with
// a narrow gather_subset so the legacy setup-on-Windows crash is still
// dodged. Windows hosts run a `win_shell` that queries CIM
// (Win32_OperatingSystem + Win32_ComputerSystem) and emits the
// markers itself; vendor strings drive a small lookup table to
// produce a canonical virtualization type that matches what
// ansible_virtualization_type would have returned.
func writePlatformDetectTasks(b *bytes.Buffer) {
	b.WriteString("    - name: gather platform facts (unix)\n")
	b.WriteString("      ansible.builtin.setup:\n")
	b.WriteString("        gather_subset:\n")
	b.WriteString("          - '!all'\n")
	b.WriteString("          - min\n")
	b.WriteString("          - distribution\n")
	b.WriteString("          - virtual\n")
	b.WriteString("      when: not (sw_is_windows | default(false) | bool)\n")
	b.WriteString("    - name: emit OS family (unix)\n")
	b.WriteString("      ansible.builtin.debug:\n")
	b.WriteString("        msg: '" + osFamilyMarker + " {{ ansible_system | default(\"\") }}'\n")
	b.WriteString("      when: not (sw_is_windows | default(false) | bool)\n")
	b.WriteString("    - name: emit OS distribution (unix)\n")
	b.WriteString("      ansible.builtin.debug:\n")
	b.WriteString("        msg: '" + osDistributionMarker + " {{ ansible_distribution | default(\"\") }}|{{ ansible_distribution_version | default(\"\") }}'\n")
	b.WriteString("      when: not (sw_is_windows | default(false) | bool)\n")
	b.WriteString("    - name: emit virtualization (unix)\n")
	b.WriteString("      ansible.builtin.debug:\n")
	b.WriteString("        msg: '" + virtualizationMarker + " {{ ansible_virtualization_type | default(\"\") }}|{{ ansible_virtualization_role | default(\"\") }}'\n")
	b.WriteString("      when: not (sw_is_windows | default(false) | bool)\n")
	// Windows path: gather facts via win_shell, then surface each
	// marker through ansible.builtin.debug. The default callback
	// hides win_shell/win_command stdout but renders debug.msg,
	// so this mirrors the unix-branch structure (one gather + three
	// emits) instead of trying to read win_shell stdout directly.
	b.WriteString("    - name: gather platform facts (windows)\n")
	b.WriteString("      ansible.windows.win_shell: |\n")
	b.WriteString("        $os = Get-CimInstance Win32_OperatingSystem\n")
	b.WriteString("        $cs = Get-CimInstance Win32_ComputerSystem\n")
	b.WriteString("        $virt = ''\n")
	b.WriteString("        $vendor = \"$($cs.Manufacturer) $($cs.Model)\"\n")
	b.WriteString("        switch -Wildcard ($vendor) {\n")
	b.WriteString("          '*VMware*'                   { $virt = 'vmware'; break }\n")
	b.WriteString("          '*Microsoft*Virtual*'        { $virt = 'hyperv'; break }\n")
	b.WriteString("          '*Hyper-V*'                  { $virt = 'hyperv'; break }\n")
	b.WriteString("          '*innotek*VirtualBox*'       { $virt = 'virtualbox'; break }\n")
	b.WriteString("          '*VirtualBox*'               { $virt = 'virtualbox'; break }\n")
	b.WriteString("          '*QEMU*'                     { $virt = 'kvm'; break }\n")
	b.WriteString("          '*Xen*'                      { $virt = 'xen'; break }\n")
	b.WriteString("          '*Parallels*'                { $virt = 'parallels'; break }\n")
	b.WriteString("          '*Amazon EC2*'               { $virt = 'xen'; break }\n")
	b.WriteString("          '*Google Compute Engine*'    { $virt = 'kvm'; break }\n")
	b.WriteString("        }\n")
	b.WriteString("        Write-Output $os.Caption\n")
	b.WriteString("        Write-Output $os.Version\n")
	b.WriteString("        Write-Output $virt\n")
	b.WriteString("      when: sw_is_windows | default(false) | bool\n")
	b.WriteString("      failed_when: false\n")
	b.WriteString("      changed_when: false\n")
	b.WriteString("      register: sw_winplatform\n")
	b.WriteString("    - name: emit OS family (windows)\n")
	b.WriteString("      ansible.builtin.debug:\n")
	b.WriteString("        msg: '" + osFamilyMarker + " Windows'\n")
	b.WriteString("      when: sw_is_windows | default(false) | bool\n")
	b.WriteString("    - name: emit OS distribution (windows)\n")
	b.WriteString("      ansible.builtin.debug:\n")
	b.WriteString("        msg: '" + osDistributionMarker + " {{ sw_winplatform.stdout_lines[0] | default(\"\") }}|{{ sw_winplatform.stdout_lines[1] | default(\"\") }}'\n")
	b.WriteString("      when: sw_is_windows | default(false) | bool\n")
	b.WriteString("    - name: emit virtualization (windows)\n")
	b.WriteString("      ansible.builtin.debug:\n")
	b.WriteString("        msg: '" + virtualizationMarker + " {{ sw_winplatform.stdout_lines[2] | default(\"\") }}|{{ \"guest\" if (sw_winplatform.stdout_lines[2] | default(\"\")) else \"NA\" }}'\n")
	b.WriteString("      when: sw_is_windows | default(false) | bool\n")
}

// PlatformFacts is the parsed shape of the SW_OS_FAMILY /
// SW_OS_DISTRIBUTION / SW_VIRTUALIZATION marker triple. Empty fields
// reflect "marker absent" or (for Virtualization) "bare metal".
// OSDistribution is rendered for display: "<distribution> <version>",
// or just "<distribution>" when version is empty.
type PlatformFacts struct {
	OSFamily       string
	OSDistribution string
	Virtualization string
}

// parsePlatformFacts extracts the three platform markers from the
// inspect playbook's stdout. Repeated markers (e.g. ansible's
// per-host fanout in stdout) win on first encounter so per-task
// ordering is stable. Bare-metal hosts are detected by
// virtualization role != "guest" — ansible reports role="host" for
// a KVM hypervisor itself, which we treat as bare-metal because the
// host is physical regardless of what it hosts.
func parsePlatformFacts(stdout []byte) PlatformFacts {
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var pf PlatformFacts
	seenFamily := false
	seenDistro := false
	seenVirt := false
	for scanner.Scan() {
		line := scanner.Text()
		// Each block evaluates the same line independently because
		// win_shell tasks pack all three markers into one `stdout`
		// JSON field separated by literal `\r\n` escapes — a single
		// scanner line can carry all three values at once.
		if !seenFamily {
			if idx := strings.Index(line, osFamilyMarker); idx >= 0 {
				pf.OSFamily = extractMarkerValue(line[idx+len(osFamilyMarker):])
				seenFamily = true
			}
		}
		if !seenDistro {
			if idx := strings.Index(line, osDistributionMarker); idx >= 0 {
				rest := extractMarkerValue(line[idx+len(osDistributionMarker):])
				parts := strings.SplitN(rest, "|", 2)
				name := strings.TrimSpace(parts[0])
				ver := ""
				if len(parts) > 1 {
					ver = strings.TrimSpace(parts[1])
				}
				switch {
				case name != "" && ver != "":
					pf.OSDistribution = name + " " + ver
				default:
					pf.OSDistribution = name
				}
				seenDistro = true
			}
		}
		if !seenVirt {
			if idx := strings.Index(line, virtualizationMarker); idx >= 0 {
				rest := extractMarkerValue(line[idx+len(virtualizationMarker):])
				parts := strings.SplitN(rest, "|", 2)
				typ := strings.ToLower(strings.TrimSpace(parts[0]))
				role := ""
				if len(parts) > 1 {
					role = strings.ToLower(strings.TrimSpace(parts[1]))
				}
				// Only mark virtual when role explicitly says "guest"
				// — a hypervisor (role=host) running on physical iron
				// stays bare-metal in our model.
				if role == "guest" {
					pf.Virtualization = typ
				} else {
					pf.Virtualization = ""
				}
				seenVirt = true
			}
		}
	}
	return pf
}

// extractMarkerValue isolates a marker's payload from the rest of
// the ansible-callback line. Stops at the first JSON-escape `\`
// (so a Windows `win_shell` stdout that packs multiple markers
// into one line via literal `\r\n` doesn't bleed the next marker's
// text into this one's value) or closing `"`, then trims whitespace.
func extractMarkerValue(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' || c == '"' {
			s = s[:i]
			break
		}
	}
	return strings.TrimSpace(s)
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
