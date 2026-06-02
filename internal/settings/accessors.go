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

// ProbeIntervalSeconds returns the reachability cadence, falling
// back to DefaultProbeIntervalSeconds on unset/unparseable/out-of-
// range values. The probe loop reads this on every Tick so a
// settings change takes effect at the next cycle without restart.
func ProbeIntervalSeconds(store Store) int {
	return clampedSetting(store, KeyProbeIntervalSeconds,
		DefaultProbeIntervalSeconds, MinProbeIntervalSeconds, MaxProbeIntervalSeconds)
}

// SetProbeIntervalSeconds validates and persists the cadence.
func SetProbeIntervalSeconds(store Store, n int) error {
	return setBoundedSetting(store, KeyProbeIntervalSeconds, n,
		MinProbeIntervalSeconds, MaxProbeIntervalSeconds, "probe_interval_seconds")
}

// ProbeFailureThreshold returns the number of consecutive failures
// required to mark a system unreachable.
func ProbeFailureThreshold(store Store) int {
	return clampedSetting(store, KeyProbeFailureThreshold,
		DefaultProbeFailureThreshold, MinProbeFailureThreshold, MaxProbeFailureThreshold)
}

// SetProbeFailureThreshold validates and persists the threshold.
func SetProbeFailureThreshold(store Store, n int) error {
	return setBoundedSetting(store, KeyProbeFailureThreshold, n,
		MinProbeFailureThreshold, MaxProbeFailureThreshold, "probe_failure_threshold")
}

// ProbeSuccessThreshold returns the number of consecutive successes
// required to mark a system reachable.
func ProbeSuccessThreshold(store Store) int {
	return clampedSetting(store, KeyProbeSuccessThreshold,
		DefaultProbeSuccessThreshold, MinProbeSuccessThreshold, MaxProbeSuccessThreshold)
}

// SetProbeSuccessThreshold validates and persists the threshold.
func SetProbeSuccessThreshold(store Store, n int) error {
	return setBoundedSetting(store, KeyProbeSuccessThreshold, n,
		MinProbeSuccessThreshold, MaxProbeSuccessThreshold, "probe_success_threshold")
}

// ScheduleMisfireGraceSeconds returns how late a scheduled run may
// fire before it is treated as missed and rescheduled, falling back to
// DefaultScheduleMisfireGraceSeconds on unset/unparseable/out-of-range
// values. The schedule ticker reads this on every tick so a change
// takes effect at the next cycle without a restart.
func ScheduleMisfireGraceSeconds(store Store) int {
	return clampedSetting(store, KeyScheduleMisfireGraceSeconds,
		DefaultScheduleMisfireGraceSeconds, MinScheduleMisfireGraceSeconds, MaxScheduleMisfireGraceSeconds)
}

// SetScheduleMisfireGraceSeconds validates and persists the grace.
func SetScheduleMisfireGraceSeconds(store Store, n int) error {
	return setBoundedSetting(store, KeyScheduleMisfireGraceSeconds, n,
		MinScheduleMisfireGraceSeconds, MaxScheduleMisfireGraceSeconds, "schedule_misfire_grace_seconds")
}

// AlertEvalIntervalSeconds returns the cadence at which the alert
// evaluator runs, falling back to DefaultAlertEvalIntervalSeconds on
// unset/unparseable/out-of-range values. The ticker reads this on every
// cycle so a change takes effect on the next tick without a restart.
func AlertEvalIntervalSeconds(store Store) int {
	return clampedSetting(store, KeyAlertEvalIntervalSeconds,
		DefaultAlertEvalIntervalSeconds, MinAlertEvalIntervalSeconds, MaxAlertEvalIntervalSeconds)
}

// SetAlertEvalIntervalSeconds validates and persists the cadence.
func SetAlertEvalIntervalSeconds(store Store, n int) error {
	return setBoundedSetting(store, KeyAlertEvalIntervalSeconds, n,
		MinAlertEvalIntervalSeconds, MaxAlertEvalIntervalSeconds, "alert_eval_interval_seconds")
}

// clampedSetting reads key, falls back to defaultValue on
// unset/unparseable/below-min, and caps to max. Shared by the
// three new probe accessors so each stays a one-liner.
func clampedSetting(store Store, key string, defaultValue, minValue, maxValue int) int {
	if store == nil {
		return defaultValue
	}
	raw, err := store.Get(key)
	if err != nil {
		return defaultValue
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < minValue {
		return defaultValue
	}
	if n > maxValue {
		return maxValue
	}
	return n
}

// setBoundedSetting validates n against [minValue, maxValue] and
// persists. Shared by the three new probe setters.
func setBoundedSetting(store Store, key string, n, minValue, maxValue int, displayName string) error {
	if store == nil {
		return errors.New("settings: store is nil")
	}
	if n < minValue || n > maxValue {
		return fmt.Errorf("%w: %s must be between %d and %d",
			ErrInvalid, displayName, minValue, maxValue)
	}
	return store.Set(key, strconv.Itoa(n))
}
