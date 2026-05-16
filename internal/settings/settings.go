// SPDX-License-Identifier: Apache-2.0

// Package settings owns the cross-cutting "instance-wide scalar
// configuration" substrate. The first setting in this package is
// run_history_limit (used by the updater_runs trim-on-insert path);
// future scalar settings slot into the same shape — a string-encoded
// value behind a typed accessor with a hard-coded default.
//
// The store is intentionally type-agnostic: every value lives in a
// single TEXT column. Validation and coercion happen above the store
// in the typed accessors so each setting can define its own parse
// rules without bloating the persistence layer.
package settings

import "errors"

// KeyRunHistoryLimit is the per-system cap on updater_runs rows.
// Stored as a string-encoded integer; DefaultRunHistoryLimit
// applies when the setting is unset or unparseable.
const KeyRunHistoryLimit = "run_history_limit"

// DefaultRunHistoryLimit caps each system's updater_runs history at
// this many rows when the setting is unset. 100 is a homelab-scale
// default: enough to retain a week of routine activity without
// inflating the DB.
const DefaultRunHistoryLimit = 100

// MinRunHistoryLimit guards against a value that would effectively
// disable history retention. Going below this caps SET requests
// with a 400 — operators who want "no history" should disable the
// updater entirely.
const MinRunHistoryLimit = 1

// MaxRunHistoryLimit caps the upper bound so a typo can't blow up
// the trim cost. 10k per system is well beyond any homelab fleet
// and still trims in a single statement.
const MaxRunHistoryLimit = 10000

// ErrNotFound is returned by Store.Get when no row exists for the
// requested key. Typed accessors translate this to the matching
// default rather than propagating the error.
var ErrNotFound = errors.New("settings: not found")

// ErrInvalid is returned when a coerced value falls outside its
// declared bounds (e.g. run_history_limit below MinRunHistoryLimit).
// The handler maps this to 400.
var ErrInvalid = errors.New("settings: invalid value")

// Store is the persistence boundary for instance-wide settings.
// SQLiteStore is the production implementation. The interface
// keeps both methods stringly-typed; coercion lives in the typed
// accessors so callers don't pay a round-trip through json for a
// scalar.
type Store interface {
	// Get returns the stored string value for key, or ErrNotFound
	// when no row exists. Callers should generally prefer the
	// typed accessors (RunHistoryLimit, ...) which fall back to
	// defaults.
	Get(key string) (string, error)
	// Set stores value verbatim for key. Validation happens in
	// the typed-setter path; the store does not parse.
	Set(key, value string) error
	// All returns every stored key/value pair. Used by the admin
	// endpoint to materialise the page in one round trip.
	All() (map[string]string, error)
}
