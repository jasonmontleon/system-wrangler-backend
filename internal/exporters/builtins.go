// SPDX-License-Identifier: Apache-2.0

package exporters

import (
	_ "embed"
)

//go:embed builtins/dnf/install.yml
var builtinDNFInstall []byte

//go:embed builtins/dnf/status.yml
var builtinDNFStatus []byte

//go:embed builtins/pacman/install.yml
var builtinPacmanInstall []byte

//go:embed builtins/pacman/status.yml
var builtinPacmanStatus []byte

//go:embed builtins/apk/install.yml
var builtinAPKInstall []byte

//go:embed builtins/apk/status.yml
var builtinAPKStatus []byte

// Builtins returns every code-registered exporter installer. Order
// is stable so callers that don't sort still produce deterministic
// output. The registry calls this once at startup and merges the
// result into its in-memory map.
//
// Each builtin pairs with the updater package manager of the same
// name (builtin.dnf / builtin.pacman / builtin.apk), so a system's
// detected pkg managers map straight onto exporter availability.
func Builtins() []Definition {
	return []Definition{
		{
			ID:                  "builtin.dnf.exporter",
			Source:              SourceBuiltin,
			DisplayName:         "dnf — node_exporter",
			Description:         "Fedora / RHEL / CentOS Stream node_exporter via the node-exporter package. Binds 127.0.0.1:9100 in localhost mode.",
			AppliesToPkgManager: "builtin.dnf",
			ExporterKind:        KindNodeExporter,
			BindPort:            9100,
			InstallPlaybook:     builtinDNFInstall,
			StatusPlaybook:      builtinDNFStatus,
		},
		{
			ID:                  "builtin.pacman.exporter",
			Source:              SourceBuiltin,
			DisplayName:         "pacman — node_exporter",
			Description:         "Arch Linux node_exporter via the prometheus-node-exporter package. Binds 127.0.0.1:9100 in localhost mode via a systemd drop-in override.",
			AppliesToPkgManager: "builtin.pacman",
			ExporterKind:        KindNodeExporter,
			BindPort:            9100,
			InstallPlaybook:     builtinPacmanInstall,
			StatusPlaybook:      builtinPacmanStatus,
		},
		{
			ID:                  "builtin.apk.exporter",
			Source:              SourceBuiltin,
			DisplayName:         "apk — node_exporter (Alpine + OpenWrt)",
			Description:         "Alpine: prometheus-node-exporter (Go binary, OpenRC, /etc/conf.d/node-exporter). OpenWrt: prometheus-node-exporter-lua (Lua reimplementation, procd, UCI). Both bind 127.0.0.1:9100 and exposes node_* metrics in the Prometheus exposition format. OpenWrt's Lua build emits a router-appropriate subset — disk / filesystem panels may be empty.",
			AppliesToPkgManager: "builtin.apk",
			ExporterKind:        KindNodeExporter,
			BindPort:            9100,
			InstallPlaybook:     builtinAPKInstall,
			StatusPlaybook:      builtinAPKStatus,
		},
	}
}
