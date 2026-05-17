// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	_ "embed"
)

//go:embed builtins/dnf/check.yml
var builtinDNFCheck []byte

//go:embed builtins/dnf/apply.yml
var builtinDNFApply []byte

//go:embed builtins/apt/check.yml
var builtinAPTCheck []byte

//go:embed builtins/apt/apply.yml
var builtinAPTApply []byte

//go:embed builtins/snap/check.yml
var builtinSnapCheck []byte

//go:embed builtins/snap/apply.yml
var builtinSnapApply []byte

//go:embed builtins/flatpak/check.yml
var builtinFlatpakCheck []byte

//go:embed builtins/flatpak/apply.yml
var builtinFlatpakApply []byte

// Builtins returns every code-registered updater. Order is stable so
// callers that don't sort still produce deterministic output. The
// registry calls this once at startup and merges the result into
// its in-memory map.
func Builtins() []Definition {
	return []Definition{
		{
			ID:            "builtin.dnf",
			Source:        SourceBuiltin,
			DisplayName:   "dnf",
			Description:   "Fedora / RHEL / CentOS Stream package manager",
			DetectBinary:  "dnf",
			CheckPlaybook: builtinDNFCheck,
			ApplyPlaybook: builtinDNFApply,
		},
		{
			ID:            "builtin.apt",
			Source:        SourceBuiltin,
			DisplayName:   "apt",
			Description:   "Debian / Ubuntu package manager",
			DetectBinary:  "apt",
			CheckPlaybook: builtinAPTCheck,
			ApplyPlaybook: builtinAPTApply,
		},
		{
			ID:            "builtin.snap",
			Source:        SourceBuiltin,
			DisplayName:   "snap",
			Description:   "Canonical snap packages",
			DetectBinary:  "snap",
			CheckPlaybook: builtinSnapCheck,
			ApplyPlaybook: builtinSnapApply,
		},
		{
			ID:            "builtin.flatpak",
			Source:        SourceBuiltin,
			DisplayName:   "flatpak",
			Description:   "Flatpak desktop applications (system installation)",
			DetectBinary:  "flatpak",
			CheckPlaybook: builtinFlatpakCheck,
			ApplyPlaybook: builtinFlatpakApply,
		},
	}
}
