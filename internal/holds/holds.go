// SPDX-License-Identifier: Apache-2.0

// Package holds owns the managed_holds table — the record of which
// (system, updater, pattern) triples System Wrangler itself placed on
// a host via a manager-native hold command (apt-mark hold, brew pin,
// snap refresh --hold, flatpak mask, …). Hold-based managers flip a
// persistent flag on the host, so without tracking what *we* set we
// couldn't tell our holds apart from holds an operator placed via
// direct SSH. The v1 UX — exclusion table is source of truth, removing
// a row stops the skip on the next Apply — needs that distinction to
// avoid clearing operator-set holds we never owned.
//
// Source of truth for "what should be held" remains
// exclusions.package_exclusions; managed_holds answers only the
// narrower "what did SW already set on this host?" question.
package holds

import (
	"errors"
	"time"
)

// Hold is one persisted row. SetAt is recorded for diagnostics — the
// reconcile loop doesn't use it.
type Hold struct {
	SystemID string    `json:"systemId"`
	Updater  string    `json:"updater"`
	Pattern  string    `json:"pattern"`
	SetAt    time.Time `json:"setAt"`
}

// ErrInvalid is returned for input-shape failures (empty system_id /
// updater id). Callers translate to 400 / log + skip as appropriate.
var ErrInvalid = errors.New("holds: invalid input")
