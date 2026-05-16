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
