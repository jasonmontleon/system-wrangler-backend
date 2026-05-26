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

//go:embed builtins/pacman/check.yml
var builtinPacmanCheck []byte

//go:embed builtins/pacman/apply.yml
var builtinPacmanApply []byte

//go:embed builtins/zypper/check.yml
var builtinZypperCheck []byte

//go:embed builtins/zypper/apply.yml
var builtinZypperApply []byte

//go:embed builtins/apk/check.yml
var builtinAPKCheck []byte

//go:embed builtins/apk/apply.yml
var builtinAPKApply []byte

//go:embed builtins/pkg/check.yml
var builtinPkgCheck []byte

//go:embed builtins/pkg/apply.yml
var builtinPkgApply []byte

//go:embed builtins/pkg_add/check.yml
var builtinPkgAddCheck []byte

//go:embed builtins/pkg_add/apply.yml
var builtinPkgAddApply []byte

//go:embed builtins/pkgin/check.yml
var builtinPkginCheck []byte

//go:embed builtins/pkgin/apply.yml
var builtinPkginApply []byte

//go:embed builtins/winget/check.yml
var builtinWingetCheck []byte

//go:embed builtins/winget/apply.yml
var builtinWingetApply []byte

//go:embed builtins/xbps/check.yml
var builtinXBPSCheck []byte

//go:embed builtins/xbps/apply.yml
var builtinXBPSApply []byte

//go:embed builtins/eopkg/check.yml
var builtinEopkgCheck []byte

//go:embed builtins/eopkg/apply.yml
var builtinEopkgApply []byte

//go:embed builtins/brew/check.yml
var builtinBrewCheck []byte

//go:embed builtins/brew/apply.yml
var builtinBrewApply []byte

//go:embed builtins/mas/check.yml
var builtinMasCheck []byte

//go:embed builtins/mas/apply.yml
var builtinMasApply []byte

//go:embed builtins/softwareupdate/check.yml
var builtinSoftwareUpdateCheck []byte

//go:embed builtins/softwareupdate/apply.yml
var builtinSoftwareUpdateApply []byte

//go:embed builtins/fwupdmgr/check.yml
var builtinFwupdmgrCheck []byte

//go:embed builtins/syspatch/check.yml
var builtinSyspatchCheck []byte

//go:embed builtins/syspatch/apply.yml
var builtinSyspatchApply []byte

//go:embed builtins/chocolatey/check.yml
var builtinChocolateyCheck []byte

//go:embed builtins/chocolatey/apply.yml
var builtinChocolateyApply []byte

//go:embed builtins/scoop/check.yml
var builtinScoopCheck []byte

//go:embed builtins/scoop/apply.yml
var builtinScoopApply []byte

//go:embed builtins/windowsupdate/check.yml
var builtinWindowsUpdateCheck []byte

//go:embed builtins/windowsupdate/apply.yml
var builtinWindowsUpdateApply []byte

// Builtins returns every code-registered updater. Order is stable so
// callers that don't sort still produce deterministic output. The
// registry calls this once at startup and merges the result into
// its in-memory map.
func Builtins() []Definition {
	return []Definition{
		{
			ID:                 "builtin.dnf",
			Source:             SourceBuiltin,
			DisplayName:        "dnf",
			Description:        "Fedora / RHEL / CentOS Stream package manager",
			DetectBinary:       "dnf",
			CheckPlaybook:      builtinDNFCheck,
			ApplyPlaybook:      builtinDNFApply,
			SupportsExclusions: true,
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
		{
			ID:                 "builtin.pacman",
			Source:             SourceBuiltin,
			DisplayName:        "pacman",
			Description:        "Arch Linux / Manjaro / EndeavourOS package manager",
			DetectBinary:       "pacman",
			CheckPlaybook:      builtinPacmanCheck,
			ApplyPlaybook:      builtinPacmanApply,
			SupportsExclusions: true,
		},
		{
			ID:                 "builtin.zypper",
			Source:             SourceBuiltin,
			DisplayName:        "zypper",
			Description:        "openSUSE / SLES package manager",
			DetectBinary:       "zypper",
			CheckPlaybook:      builtinZypperCheck,
			ApplyPlaybook:      builtinZypperApply,
			SupportsExclusions: true,
		},
		{
			ID:            "builtin.apk",
			Source:        SourceBuiltin,
			DisplayName:   "apk",
			Description:   "Alpine Linux / OpenWRT package manager",
			DetectBinary:  "apk",
			CheckPlaybook: builtinAPKCheck,
			ApplyPlaybook: builtinAPKApply,
		},
		{
			ID:                 "builtin.pkg",
			Source:             SourceBuiltin,
			DisplayName:        "pkg",
			Description:        "FreeBSD package manager",
			DetectBinary:       "pkg",
			CheckPlaybook:      builtinPkgCheck,
			ApplyPlaybook:      builtinPkgApply,
			SupportsExclusions: true,
		},
		{
			ID:            "builtin.pkg_add",
			Source:        SourceBuiltin,
			DisplayName:   "pkg_add",
			Description:   "OpenBSD package manager",
			DetectBinary:  "pkg_add",
			CheckPlaybook: builtinPkgAddCheck,
			ApplyPlaybook: builtinPkgAddApply,
		},
		{
			ID:            "builtin.pkgin",
			Source:        SourceBuiltin,
			DisplayName:   "pkgin",
			Description:   "NetBSD pkgsrc binary package manager",
			DetectBinary:  "pkgin",
			CheckPlaybook: builtinPkginCheck,
			ApplyPlaybook: builtinPkginApply,
		},
		{
			ID:                 "builtin.winget",
			Source:             SourceBuiltin,
			DisplayName:        "winget",
			Description:        "Windows Package Manager (preinstalled on modern Windows)",
			DetectBinary:       "winget",
			CheckPlaybook:      builtinWingetCheck,
			ApplyPlaybook:      builtinWingetApply,
			SupportsExclusions: true,
		},
		{
			ID:            "builtin.xbps",
			Source:        SourceBuiltin,
			DisplayName:   "xbps",
			Description:   "Void Linux package manager",
			DetectBinary:  "xbps-install",
			CheckPlaybook: builtinXBPSCheck,
			ApplyPlaybook: builtinXBPSApply,
		},
		{
			ID:            "builtin.eopkg",
			Source:        SourceBuiltin,
			DisplayName:   "eopkg",
			Description:   "Solus package manager",
			DetectBinary:  "eopkg",
			CheckPlaybook: builtinEopkgCheck,
			ApplyPlaybook: builtinEopkgApply,
		},
		{
			ID:            "builtin.brew",
			Source:        SourceBuiltin,
			DisplayName:   "brew",
			Description:   "macOS Homebrew package manager (runs unprivileged)",
			DetectBinary:  "brew",
			CheckPlaybook: builtinBrewCheck,
			ApplyPlaybook: builtinBrewApply,
		},
		{
			ID:            "builtin.mas",
			Source:        SourceBuiltin,
			DisplayName:   "mas",
			Description:   "macOS Mac App Store via mas-cli (requires signed-in App Store session)",
			DetectBinary:  "mas",
			CheckPlaybook: builtinMasCheck,
			ApplyPlaybook: builtinMasApply,
		},
		{
			ID:            "builtin.softwareupdate",
			Source:        SourceBuiltin,
			DisplayName:   "softwareupdate",
			Description:   "macOS system software updates (major OS patches require reboot)",
			DetectBinary:  "softwareupdate",
			CheckPlaybook: builtinSoftwareUpdateCheck,
			ApplyPlaybook: builtinSoftwareUpdateApply,
		},
		{
			ID:            "builtin.fwupdmgr",
			Source:        SourceBuiltin,
			DisplayName:   "fwupdmgr",
			Description:   "Firmware updates via fwupd / LVFS (check-only — never auto-applied)",
			DetectBinary:  "fwupdmgr",
			CheckPlaybook: builtinFwupdmgrCheck,
			CheckOnly:     true,
		},
		{
			ID:            "builtin.syspatch",
			Source:        SourceBuiltin,
			DisplayName:   "syspatch",
			Description:   "OpenBSD base / kernel security patches (reboot required for kernel-tier patches)",
			DetectBinary:  "syspatch",
			CheckPlaybook: builtinSyspatchCheck,
			ApplyPlaybook: builtinSyspatchApply,
		},
		{
			ID:                 "builtin.chocolatey",
			Source:             SourceBuiltin,
			DisplayName:        "chocolatey",
			Description:        "Windows Chocolatey package manager",
			DetectBinary:       "choco",
			CheckPlaybook:      builtinChocolateyCheck,
			ApplyPlaybook:      builtinChocolateyApply,
			SupportsExclusions: true,
		},
		{
			ID:            "builtin.scoop",
			Source:        SourceBuiltin,
			DisplayName:   "scoop",
			Description:   "Windows Scoop package manager (user-scoped; PATH must include scoop's shims directory)",
			DetectBinary:  "scoop",
			CheckPlaybook: builtinScoopCheck,
			ApplyPlaybook: builtinScoopApply,
		},
		{
			ID:            "builtin.windowsupdate",
			Source:        SourceBuiltin,
			DisplayName:   "windowsupdate",
			Description:   "Windows Update via ansible.windows.win_updates (major OS patches; reboots are operator-triggered)",
			DetectBinary:  "UsoClient",
			CheckPlaybook: builtinWindowsUpdateCheck,
			ApplyPlaybook: builtinWindowsUpdateApply,
		},
	}
}
