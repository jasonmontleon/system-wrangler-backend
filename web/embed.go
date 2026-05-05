// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import "embed"

// Dist holds the built frontend assets. Populated at build time by copying
// the frontend project's `dist/` output into `web/dist/`. The `all:` prefix
// is required so dotfiles (e.g. .gitkeep) and Vite's hashed asset filenames
// are both included.
//
//go:embed all:dist
var Dist embed.FS
