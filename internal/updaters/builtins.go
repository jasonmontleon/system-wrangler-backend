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
		{
			ID:            "builtin.pacman",
			Source:        SourceBuiltin,
			DisplayName:   "pacman",
			Description:   "Arch Linux / Manjaro / EndeavourOS package manager",
			DetectBinary:  "pacman",
			CheckPlaybook: builtinPacmanCheck,
			ApplyPlaybook: builtinPacmanApply,
		},
		{
			ID:            "builtin.zypper",
			Source:        SourceBuiltin,
			DisplayName:   "zypper",
			Description:   "openSUSE / SLES package manager",
			DetectBinary:  "zypper",
			CheckPlaybook: builtinZypperCheck,
			ApplyPlaybook: builtinZypperApply,
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
			ID:            "builtin.pkg",
			Source:        SourceBuiltin,
			DisplayName:   "pkg",
			Description:   "FreeBSD package manager",
			DetectBinary:  "pkg",
			CheckPlaybook: builtinPkgCheck,
			ApplyPlaybook: builtinPkgApply,
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
			ID:            "builtin.winget",
			Source:        SourceBuiltin,
			DisplayName:   "winget",
			Description:   "Windows Package Manager (preinstalled on modern Windows)",
			DetectBinary:  "winget",
			CheckPlaybook: builtinWingetCheck,
			ApplyPlaybook: builtinWingetApply,
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
	}
}
