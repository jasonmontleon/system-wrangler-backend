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

import (
	"errors"
	"strings"
)

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

// KeyUpdateConcurrencyLimit caps how many check/apply runs the
// Runner will execute simultaneously. Extra requests wait in a FIFO
// queue and start as in-flight runs complete.
const KeyUpdateConcurrencyLimit = "update_concurrency_limit"

// DefaultUpdateConcurrencyLimit picks a small parallelism that suits
// a homelab without saturating the ansible/ssh stack. Operators with
// a beefier control node can raise it.
const DefaultUpdateConcurrencyLimit = 4

// MinUpdateConcurrencyLimit guards against a value that would
// effectively halt the runner. A value of 1 is the serial floor.
const MinUpdateConcurrencyLimit = 1

// MaxUpdateConcurrencyLimit bounds the upper end. 100 is plenty for
// a homelab fleet and still leaves headroom against the OS's open-
// file and child-process limits.
const MaxUpdateConcurrencyLimit = 100

// KeyProbeIntervalSeconds is the cadence at which the reachability
// loop visits every system. Stored as a string-encoded integer
// number of seconds.
const KeyProbeIntervalSeconds = "probe_interval_seconds"

// DefaultProbeIntervalSeconds matches the pre-settings hardcoded
// value so an unconfigured instance behaves identically to one
// pinned at the default.
const DefaultProbeIntervalSeconds = 30

// MinProbeIntervalSeconds prevents an operator from setting a value
// that would hammer the fleet (and the dialer's connection table)
// with sub-5-second probing.
const MinProbeIntervalSeconds = 5

// MaxProbeIntervalSeconds caps at one hour. Slower than that and
// "are we live?" answers stop being meaningful as a health signal.
const MaxProbeIntervalSeconds = 3600

// KeyProbeFailureThreshold is the number of consecutive failed
// probes required to flip a system to unreachable. Stored as a
// string-encoded integer.
const KeyProbeFailureThreshold = "probe_failure_threshold"

// DefaultProbeFailureThreshold matches the pre-threshold behavior:
// one failure flips immediately.
const DefaultProbeFailureThreshold = 1

// MinProbeFailureThreshold is 1: zero would mean "never mark
// unreachable" which would silently mask the whole feature.
const MinProbeFailureThreshold = 1

// MaxProbeFailureThreshold caps the hysteresis at 10. Beyond that
// the lag between the system being down and the dashboard noticing
// crosses into "useless".
const MaxProbeFailureThreshold = 10

// KeyProbeSuccessThreshold is the number of consecutive successful
// probes required to flip a system back to reachable. Stored as
// a string-encoded integer.
const KeyProbeSuccessThreshold = "probe_success_threshold"

// DefaultProbeSuccessThreshold matches the pre-threshold behavior:
// one success flips immediately.
const DefaultProbeSuccessThreshold = 1

// MinProbeSuccessThreshold mirrors the failure-side reasoning.
const MinProbeSuccessThreshold = 1

// MaxProbeSuccessThreshold mirrors the failure-side cap.
const MaxProbeSuccessThreshold = 10

// KeyScheduleMisfireGraceSeconds is how late a scheduled run may fire
// before the ticker treats it as missed and reschedules it to its next
// occurrence without running. This is what stops a fleet-wide spike of
// catch-up runs when the server comes back from an outage. Stored as a
// string-encoded integer number of seconds.
const KeyScheduleMisfireGraceSeconds = "schedule_misfire_grace_seconds"

// DefaultScheduleMisfireGraceSeconds is two minutes: generous enough to
// absorb tick jitter and a quick redeploy (which should still fire)
// while skipping the longer outages that would otherwise pile work up.
const DefaultScheduleMisfireGraceSeconds = 120

// MinScheduleMisfireGraceSeconds is one ticker interval (60s). Below
// this, a schedule that came due just before a tick could be skipped
// even on a healthy server, because the tick that evaluates it runs up
// to one interval after the fire time.
const MinScheduleMisfireGraceSeconds = 60

// MaxScheduleMisfireGraceSeconds caps at one hour. A grace wider than
// that starts to defeat the purpose — long outages would again trigger
// the catch-up spike the setting exists to prevent.
const MaxScheduleMisfireGraceSeconds = 3600

// KeyAlertEvalIntervalSeconds is the cadence at which the alert
// evaluator walks the enabled rules and reconciles firing state. Stored
// as a string-encoded integer number of seconds.
const KeyAlertEvalIntervalSeconds = "alert_eval_interval_seconds"

// DefaultAlertEvalIntervalSeconds is one minute, matching the schedules
// ticker and Prometheus's default scrape granularity — evaluating
// thresholds faster than the data refreshes buys nothing.
const DefaultAlertEvalIntervalSeconds = 60

// MinAlertEvalIntervalSeconds keeps the evaluator from hammering
// Prometheus with instant queries on a tight loop.
const MinAlertEvalIntervalSeconds = 10

// MaxAlertEvalIntervalSeconds caps at one hour. Slower than that and a
// breach could persist most of an hour before an alert ever fires.
const MaxAlertEvalIntervalSeconds = 3600

// KeyRebootGraceSeconds is how long the apply-stamped reboot_required_at
// column stays authoritative in the SPA before the sw_reboot_required
// metric takes over as the sole source of truth. Stored as a
// string-encoded integer number of seconds.
const KeyRebootGraceSeconds = "reboot_grace_seconds"

// DefaultRebootGraceSeconds is two minutes. The metric's worst-case ON
// latency after a reboot becomes required is ~105s in a default deploy
// (60s textfile collector cadence + 15s Prometheus scrape + 30s SPA
// poll); 120s covers that with a small margin so the column bridges the
// gap without a "no reboot" flicker, while keeping the time-to-truth
// after a reboot short. Operators with a faster or slower scrape can
// tune it either way.
const DefaultRebootGraceSeconds = 120

// MinRebootGraceSeconds is a permissive floor. Values below the
// metric's ~105s catch-up let the column expire before the metric is
// reliable, which can show a brief post-apply flicker — but that's the
// operator's call to make, so the floor only guards against a zero or
// negative window.
const MinRebootGraceSeconds = 10

// MaxRebootGraceSeconds caps at thirty minutes. A longer grace only
// widens the window in which an apply-then-immediate-reboot shows a
// stale "reboot required" before the metric reclaims authority.
const MaxRebootGraceSeconds = 1800

// KeyShutdownGraceSeconds is how long, on receiving a shutdown signal,
// the server keeps draining in-flight runs before it exits. New runs
// are refused immediately; runs still going when the grace elapses are
// abandoned and reconciled (marked failed, locks dropped) on the next
// start. Stored as a string-encoded integer number of seconds.
const KeyShutdownGraceSeconds = "shutdown_grace_seconds"

// DefaultShutdownGraceSeconds is five minutes: long enough for a
// typical check/apply to finish cleanly during a rolling restart,
// short enough not to stall an operator who needs the server down.
const DefaultShutdownGraceSeconds = 300

// MinShutdownGraceSeconds is one minute. The container or orchestrator
// stop timeout (podman --stop-timeout, k8s terminationGracePeriodSeconds,
// systemd TimeoutStopSec) must be at least this, or the runtime SIGKILLs
// mid-drain and only startup reconciliation recovers.
const MinShutdownGraceSeconds = 60

// MaxShutdownGraceSeconds caps at thirty minutes — beyond that a stuck
// run would hold the whole shutdown hostage when it should be left for
// reconciliation instead.
const MaxShutdownGraceSeconds = 1800

// logLevelPrefix is prepended to a background-loop component name to
// form its setting key, e.g. "log_level_probe".
const logLevelPrefix = "log_level_"

// LogLevelKey returns the settings key holding the log level for a
// background loop component (one of internal/logging's Components).
func LogLevelKey(component string) string {
	return logLevelPrefix + component
}

// LogLevelComponent reverses LogLevelKey: it reports the component name
// for a log-level key, and false for any other key.
func LogLevelComponent(key string) (string, bool) {
	c, ok := strings.CutPrefix(key, logLevelPrefix)
	if !ok || c == "" {
		return "", false
	}
	return c, true
}

// DefaultLogLevel is the level a background loop logs at until an admin
// changes it: routine operational lines, no per-cycle debug churn.
const DefaultLogLevel = "info"

// LogLevels are the accepted values for a per-loop log level, ordered
// most-to-least verbose. The frontend renders the same set.
var LogLevels = []string{"debug", "info", "warn", "error"}

// validLogLevel reports whether s is one of the accepted log levels.
func validLogLevel(s string) bool {
	for _, l := range LogLevels {
		if s == l {
			return true
		}
	}
	return false
}

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
