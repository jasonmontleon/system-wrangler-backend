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

//go:embed builtins/pkg/install.yml
var builtinPkgInstall []byte

//go:embed builtins/pkg/status.yml
var builtinPkgStatus []byte

//go:embed builtins/pkgin/install.yml
var builtinPkginInstall []byte

//go:embed builtins/pkgin/status.yml
var builtinPkginStatus []byte

//go:embed builtins/pkg_add/install.yml
var builtinPkgAddInstall []byte

//go:embed builtins/pkg_add/status.yml
var builtinPkgAddStatus []byte

//go:embed builtins/apt/install.yml
var builtinAptInstall []byte

//go:embed builtins/apt/status.yml
var builtinAptStatus []byte

//go:embed builtins/xbps/install.yml
var builtinXbpsInstall []byte

//go:embed builtins/xbps/status.yml
var builtinXbpsStatus []byte

//go:embed builtins/zypper/install.yml
var builtinZypperInstall []byte

//go:embed builtins/zypper/status.yml
var builtinZypperStatus []byte

//go:embed builtins/brew/install.yml
var builtinBrewInstall []byte

//go:embed builtins/brew/status.yml
var builtinBrewStatus []byte

//go:embed builtins/winget/install.yml
var builtinWingetInstall []byte

//go:embed builtins/winget/status.yml
var builtinWingetStatus []byte

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
		{
			ID:                  "builtin.pkg.exporter",
			Source:              SourceBuiltin,
			DisplayName:         "pkg — node_exporter (FreeBSD)",
			Description:         "FreeBSD node_exporter via the node_exporter package. Binds 127.0.0.1:9100 via node_exporter_args in /etc/rc.conf and manages the service through the FreeBSD rc.d framework. Upstream node_exporter on BSDs covers a narrower collector set than Linux: CPU iowait, swap %, TCP connections, open file descriptors, and process counts are not emitted; memory used % falls back to active+wired vs active+inactive+wired+free.",
			AppliesToPkgManager: "builtin.pkg",
			ExporterKind:        KindNodeExporter,
			BindPort:            9100,
			InstallPlaybook:     builtinPkgInstall,
			StatusPlaybook:      builtinPkgStatus,
		},
		{
			ID:                  "builtin.pkgin.exporter",
			Source:              SourceBuiltin,
			DisplayName:         "pkgin — node_exporter (NetBSD)",
			Description:         "NetBSD node_exporter via the pkgsrc node_exporter package. Binds 127.0.0.1:9100 via node_exporter_flags in /etc/rc.conf and copies the rc.d script from /usr/pkg/share/examples/rc.d if not already installed. Upstream node_exporter on BSDs covers a narrower collector set than Linux: CPU iowait, swap %, TCP connections, open file descriptors, and process counts are not emitted; memory used % falls back to active+wired vs active+inactive+wired+free where available.",
			AppliesToPkgManager: "builtin.pkgin",
			ExporterKind:        KindNodeExporter,
			BindPort:            9100,
			InstallPlaybook:     builtinPkginInstall,
			StatusPlaybook:      builtinPkginStatus,
		},
		{
			ID:                  "builtin.pkg_add.exporter",
			Source:              SourceBuiltin,
			DisplayName:         "pkg_add — node_exporter (OpenBSD)",
			Description:         "OpenBSD node_exporter via the node_exporter package. Binds 127.0.0.1:9100 via rcctl set node_exporter flags and manages enable / restart through rcctl. Upstream node_exporter on BSDs covers a narrower collector set than Linux: CPU iowait, swap %, TCP connections, open file descriptors, and process counts are not emitted; memory used % falls back to active+wired vs active+inactive+wired+free where available.",
			AppliesToPkgManager: "builtin.pkg_add",
			ExporterKind:        KindNodeExporter,
			BindPort:            9100,
			InstallPlaybook:     builtinPkgAddInstall,
			StatusPlaybook:      builtinPkgAddStatus,
		},
		{
			ID:                  "builtin.apt.exporter",
			Source:              SourceBuiltin,
			DisplayName:         "apt — node_exporter (Debian + Ubuntu)",
			Description:         "Debian / Ubuntu node_exporter via the prometheus-node-exporter package. Binds 127.0.0.1:9100 in localhost mode via a systemd drop-in override on the prometheus-node-exporter service.",
			AppliesToPkgManager: "builtin.apt",
			ExporterKind:        KindNodeExporter,
			BindPort:            9100,
			InstallPlaybook:     builtinAptInstall,
			StatusPlaybook:      builtinAptStatus,
		},
		{
			ID:                  "builtin.xbps.exporter",
			Source:              SourceBuiltin,
			DisplayName:         "xbps — node_exporter (Void Linux)",
			Description:         "Void Linux node_exporter via the node_exporter package. Service supervision uses runit (sv): the package ships /etc/sv/node_exporter and the play writes /etc/sv/node_exporter/conf with OPTS forcing 127.0.0.1:9100, symlinks the service into /var/service, then sends sv term so runsv respawns with the new options.",
			AppliesToPkgManager: "builtin.xbps",
			ExporterKind:        KindNodeExporter,
			BindPort:            9100,
			InstallPlaybook:     builtinXbpsInstall,
			StatusPlaybook:      builtinXbpsStatus,
		},
		{
			ID:                  "builtin.zypper.exporter",
			Source:              SourceBuiltin,
			DisplayName:         "zypper — node_exporter (openSUSE + SLES)",
			Description:         "openSUSE / SLES node_exporter via the golang-github-prometheus-node_exporter package. Binds 127.0.0.1:9100 in localhost mode via a systemd drop-in override on the prometheus-node_exporter service (note the underscore — matches the SUSE package's unit name).",
			AppliesToPkgManager: "builtin.zypper",
			ExporterKind:        KindNodeExporter,
			BindPort:            9100,
			InstallPlaybook:     builtinZypperInstall,
			StatusPlaybook:      builtinZypperStatus,
		},
		{
			ID:                  "builtin.brew.exporter",
			Source:              SourceBuiltin,
			DisplayName:         "brew — node_exporter (macOS)",
			Description:         "macOS node_exporter via the Homebrew node_exporter formula. Runs as a per-user LaunchAgent (com.systemwrangler.node_exporter) bound to 127.0.0.1:9100. Homebrew refuses to run as root, so the play uses become: false; the LaunchAgent is loaded into the SSH user's bootstrap context. Headless monitoring requires the SSH user to stay signed in so launchd keeps the agent alive.",
			AppliesToPkgManager: "builtin.brew",
			ExporterKind:        KindNodeExporter,
			BindPort:            9100,
			InstallPlaybook:     builtinBrewInstall,
			StatusPlaybook:      builtinBrewStatus,
		},
		{
			ID:                  "builtin.winget.exporter",
			Source:              SourceBuiltin,
			DisplayName:         "winget — windows_exporter",
			Description:         "Windows windows_exporter via the Prometheus.WindowsExporter winget package. After install the play rewrites the windows_exporter service binPath via Win32_Service.Change to force --web.listen-address=127.0.0.1:9182 and enable a wider collector set (cpu,cs,logical_disk,memory,net,os,service,system,tcp) so Memory and TCP panels populate alongside the defaults. Uses the standard windows_exporter port 9182.",
			AppliesToPkgManager: "builtin.winget",
			ExporterKind:        KindWindowsExporter,
			BindPort:            9182,
			InstallPlaybook:     builtinWingetInstall,
			StatusPlaybook:      builtinWingetStatus,
		},
	}
}
