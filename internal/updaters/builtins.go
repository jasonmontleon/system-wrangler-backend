// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	_ "embed"
)

//go:embed builtins/dnf/check.yml
var builtinDNFCheck []byte

//go:embed builtins/dnf/apply.yml
var builtinDNFApply []byte

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
	}
}
