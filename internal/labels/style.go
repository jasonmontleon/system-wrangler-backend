// SPDX-License-Identifier: Apache-2.0

package labels

import (
	"errors"
	"fmt"
)

// LabelStyle is a global, key-level color override. The hybrid color
// model layers it on top of a deterministic hash → palette fallback in
// the SPA: if `label_styles[key]` exists, the chip renders in that
// color; otherwise the SPA hashes the key into the palette.
//
// Keying by `key` (not `(key, value)`) matches the dominant operator
// expectation — "make all env-* chips blue", not per-value coloring.
// That can be revisited if a real fleet pushes back on the coarseness.
type LabelStyle struct {
	Key   string `json:"key"`
	Color string `json:"color"`
}

// AllowedColors is the closed set the handler accepts. Mirrors the
// PatternFly v6 Label `color` prop so the SPA can hand the string
// straight into <Label color={...}> without translation.
var AllowedColors = []string{
	"blue", "teal", "green", "orange", "purple",
	"red", "orangered", "grey", "yellow",
}

// ErrInvalidColor is returned when a caller asks for a color outside
// AllowedColors. Handler maps it to 400.
var ErrInvalidColor = errors.New("color not in allowed set")

// ValidateColor returns ErrInvalidColor for anything outside the
// allowlist. Empty string is also rejected — callers that want to
// remove a style should DELETE the row.
func ValidateColor(color string) error {
	for _, c := range AllowedColors {
		if c == color {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrInvalidColor, color)
}
