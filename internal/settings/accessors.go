// SPDX-License-Identifier: Apache-2.0

package settings

import (
	"errors"
	"fmt"
	"strconv"
)

// RunHistoryLimit returns the integer cap on updater_runs rows per
// system, falling back to DefaultRunHistoryLimit when the setting
// is unset or unparseable. Callers should use this rather than
// Store.Get directly so the fallback is consistent.
func RunHistoryLimit(store Store) int {
	if store == nil {
		return DefaultRunHistoryLimit
	}
	raw, err := store.Get(KeyRunHistoryLimit)
	if err != nil {
		return DefaultRunHistoryLimit
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < MinRunHistoryLimit {
		return DefaultRunHistoryLimit
	}
	if n > MaxRunHistoryLimit {
		return MaxRunHistoryLimit
	}
	return n
}

// SetRunHistoryLimit validates and persists the cap. Out-of-range
// inputs return ErrInvalid; the handler maps that to 400.
func SetRunHistoryLimit(store Store, n int) error {
	if store == nil {
		return errors.New("settings: store is nil")
	}
	if n < MinRunHistoryLimit || n > MaxRunHistoryLimit {
		return fmt.Errorf("%w: run_history_limit must be between %d and %d",
			ErrInvalid, MinRunHistoryLimit, MaxRunHistoryLimit)
	}
	return store.Set(KeyRunHistoryLimit, strconv.Itoa(n))
}

// UpdateConcurrencyLimit returns the cap on simultaneously-running
// check/apply tasks across the fleet, falling back to
// DefaultUpdateConcurrencyLimit on unset/unparseable/out-of-range
// values. The Runner reads this on every Acquire so a settings
// change takes effect against the next waiter without restart.
func UpdateConcurrencyLimit(store Store) int {
	if store == nil {
		return DefaultUpdateConcurrencyLimit
	}
	raw, err := store.Get(KeyUpdateConcurrencyLimit)
	if err != nil {
		return DefaultUpdateConcurrencyLimit
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < MinUpdateConcurrencyLimit {
		return DefaultUpdateConcurrencyLimit
	}
	if n > MaxUpdateConcurrencyLimit {
		return MaxUpdateConcurrencyLimit
	}
	return n
}

// SetUpdateConcurrencyLimit validates and persists the cap. Out-of-
// range values return ErrInvalid; the handler maps that to 400.
func SetUpdateConcurrencyLimit(store Store, n int) error {
	if store == nil {
		return errors.New("settings: store is nil")
	}
	if n < MinUpdateConcurrencyLimit || n > MaxUpdateConcurrencyLimit {
		return fmt.Errorf("%w: update_concurrency_limit must be between %d and %d",
			ErrInvalid, MinUpdateConcurrencyLimit, MaxUpdateConcurrencyLimit)
	}
	return store.Set(KeyUpdateConcurrencyLimit, strconv.Itoa(n))
}
