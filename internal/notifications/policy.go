// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// DeliveryMode is how one severity's transitions reach channels.
//
//   - ModeDashboard: never delivered to channels; the alert is visible on
//     the dashboard / Alerts page only.
//   - ModeQuiet: delivered to channels, but while the clock is inside a
//     quiet window the send is deferred and flushed when the window ends.
//   - ModeAlways: delivered immediately regardless of quiet hours (paging).
type DeliveryMode string

// DeliveryMode values.
const (
	ModeDashboard DeliveryMode = "dashboard"
	ModeQuiet     DeliveryMode = "quiet"
	ModeAlways    DeliveryMode = "always"
)

// IsValid reports whether m is a known delivery mode.
func (m DeliveryMode) IsValid() bool {
	switch m {
	case ModeDashboard, ModeQuiet, ModeAlways:
		return true
	default:
		return false
	}
}

// DefaultSeverities is the out-of-the-box severity → mode mapping: info is
// dashboard-only, warnings respect quiet hours, criticals always page.
var DefaultSeverities = map[string]DeliveryMode{
	"info":     ModeDashboard,
	"warning":  ModeQuiet,
	"critical": ModeAlways,
}

// QuietWindow is one recurring quiet interval. Days lists the weekdays the
// window applies to (empty = every day); an overnight window (Start > End)
// is anchored to its start day, so Fri 22:00–08:00 covers Friday night
// into Saturday morning. Times are "HH:MM" in the policy's timezone.
type QuietWindow struct {
	Days  []time.Weekday `json:"days"`
	Start string         `json:"start"`
	End   string         `json:"end"`
}

// Policy is the global delivery policy: a per-severity delivery mode plus
// the quiet-hours schedule. It is a singleton.
type Policy struct {
	Timezone   string                  `json:"timezone"`
	Windows    []QuietWindow           `json:"windows"`
	Severities map[string]DeliveryMode `json:"severities"`
}

// PolicyInput is the operator-supplied policy accepted on PUT. It mirrors
// Policy; Validate normalizes it in place.
type PolicyInput = Policy

// DefaultPolicy is the policy in effect before an operator stores one: no
// quiet windows (nothing is ever deferred) and the default severity map.
func DefaultPolicy() Policy {
	sev := make(map[string]DeliveryMode, len(DefaultSeverities))
	for k, v := range DefaultSeverities {
		sev[k] = v
	}
	return Policy{Timezone: "UTC", Windows: []QuietWindow{}, Severities: sev}
}

// ModeFor resolves a severity to its delivery mode, falling back to the
// built-in default for that severity (and to ModeQuiet for an unknown one).
func (p Policy) ModeFor(severity string) DeliveryMode {
	if m, ok := p.Severities[severity]; ok && m.IsValid() {
		return m
	}
	if m, ok := DefaultSeverities[severity]; ok {
		return m
	}
	return ModeQuiet
}

// Validate normalizes and checks the policy, returning ErrInvalid wrapped
// with a reason. An empty timezone defaults to UTC; severity keys must be
// known and modes valid; each window's times must parse, sit in range, and
// differ.
func (p *Policy) Validate() error {
	if strings.TrimSpace(p.Timezone) == "" {
		p.Timezone = "UTC"
	}
	if _, err := time.LoadLocation(p.Timezone); err != nil {
		return fmt.Errorf("%w: timezone %q is not a valid IANA name", ErrInvalid, p.Timezone)
	}
	for sev, mode := range p.Severities {
		if _, ok := DefaultSeverities[sev]; !ok {
			return fmt.Errorf("%w: severity %q is not one of info/warning/critical", ErrInvalid, sev)
		}
		if !mode.IsValid() {
			return fmt.Errorf("%w: delivery mode %q is not one of dashboard/quiet/always", ErrInvalid, mode)
		}
	}
	for i := range p.Windows {
		w := &p.Windows[i]
		start, err := parseHHMM(w.Start)
		if err != nil {
			return fmt.Errorf("%w: window %d start: %s", ErrInvalid, i, err.Error())
		}
		end, err := parseHHMM(w.End)
		if err != nil {
			return fmt.Errorf("%w: window %d end: %s", ErrInvalid, i, err.Error())
		}
		if start == end {
			return fmt.Errorf("%w: window %d start and end must differ", ErrInvalid, i)
		}
		for _, d := range w.Days {
			if d < time.Sunday || d > time.Saturday {
				return fmt.Errorf("%w: window %d has weekday %d out of range 0-6", ErrInvalid, i, d)
			}
		}
	}
	return nil
}

// InQuietHours reports whether t falls inside any quiet window. Zero
// windows means quiet hours are off, so it always returns false.
func (p Policy) InQuietHours(t time.Time) bool {
	if len(p.Windows) == 0 {
		return false
	}
	loc, err := time.LoadLocation(p.Timezone)
	if err != nil {
		slog.Warn("notifications: bad policy timezone, using UTC", "tz", p.Timezone, "err", err)
		loc = time.UTC
	}
	lt := t.In(loc)
	day := lt.Weekday()
	minute := lt.Hour()*60 + lt.Minute()
	for _, w := range p.Windows {
		start, err := parseHHMM(w.Start)
		if err != nil {
			continue
		}
		end, err := parseHHMM(w.End)
		if err != nil || start == end {
			continue
		}
		if start < end {
			// Same-day window: in it when today is covered and the clock
			// sits in [start, end).
			if dayCovered(w.Days, day) && minute >= start && minute < end {
				return true
			}
			continue
		}
		// Overnight window starting on day D spans [D start, D+1 end): the
		// evening portion belongs to today, the morning portion to the
		// window that started yesterday.
		if dayCovered(w.Days, day) && minute >= start {
			return true
		}
		if dayCovered(w.Days, prevDay(day)) && minute < end {
			return true
		}
	}
	return false
}

// dayCovered reports whether d is in days; an empty list means every day.
func dayCovered(days []time.Weekday, d time.Weekday) bool {
	if len(days) == 0 {
		return true
	}
	for _, x := range days {
		if x == d {
			return true
		}
	}
	return false
}

func prevDay(d time.Weekday) time.Weekday {
	return time.Weekday((int(d) + 6) % 7)
}

// parseHHMM parses "HH:MM" into minutes since midnight, accepting the
// sentinel "24:00" for end-of-day.
func parseHHMM(s string) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	if !ok {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	hh, err := strconv.Atoi(h)
	if err != nil {
		return 0, fmt.Errorf("%q hour is not a number", s)
	}
	mm, err := strconv.Atoi(m)
	if err != nil {
		return 0, fmt.Errorf("%q minute is not a number", s)
	}
	if hh < 0 || mm < 0 || mm > 59 || hh > 24 || (hh == 24 && mm != 0) {
		return 0, fmt.Errorf("%q is out of range", s)
	}
	return hh*60 + mm, nil
}
