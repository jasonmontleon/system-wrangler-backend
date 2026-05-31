// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidCron is returned when a cron expression cannot be parsed.
// Callers compare with errors.Is so they don't have to depend on the
// exact wrapped message.
var ErrInvalidCron = errors.New("invalid cron expression")

// CronSchedule is a parsed 5-field POSIX cron expression. The four
// bitmask fields store allowed values for minute (0-59), hour (0-23),
// day-of-month (1-31), and month (1-12). The dow byte tracks
// day-of-week 0-6 (Sunday = 0). The two starred flags preserve
// whether the operator typed `*` for that field — needed to implement
// POSIX cron's "OR semantics when both DoM and DoW are restricted"
// rule.
type CronSchedule struct {
	expr       string
	minutes    [60]bool
	hours      [24]bool
	doms       [32]bool
	months     [13]bool
	dows       [7]bool
	domStarred bool
	dowStarred bool
}

// Expr returns the original cron expression the schedule was parsed
// from. Storing the source string lets us round-trip the value back
// to the operator without reconstructing it from bitmasks.
func (c *CronSchedule) Expr() string { return c.expr }

var monthNames = map[string]int{
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
	"jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

var dowNames = map[string]int{
	"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

// ParseCron parses a 5-field POSIX cron expression. Supported syntax
// per field: `*`, `n`, `n-m`, `n,m`, `*/k`, `n-m/k`. Month and DoW
// accept three-letter names case-insensitively. DoW value 7 is
// normalised to 0 (both mean Sunday) — this matches POSIX cron and
// is what most users expect when writing `0 0 * * 7`.
func ParseCron(expr string) (*CronSchedule, error) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return nil, fmt.Errorf("%w: expected 5 fields, got %d", ErrInvalidCron, len(fields))
	}
	c := &CronSchedule{expr: strings.TrimSpace(expr)}

	if err := parseField(fields[0], 0, 59, nil, c.minutes[:], nil); err != nil {
		return nil, fmt.Errorf("%w: minute: %s", ErrInvalidCron, err)
	}
	if err := parseField(fields[1], 0, 23, nil, c.hours[:], nil); err != nil {
		return nil, fmt.Errorf("%w: hour: %s", ErrInvalidCron, err)
	}
	domStarred, err := parseFieldStarred(fields[2], 1, 31, nil, c.doms[:])
	if err != nil {
		return nil, fmt.Errorf("%w: day-of-month: %s", ErrInvalidCron, err)
	}
	c.domStarred = domStarred
	if err := parseField(fields[3], 1, 12, monthNames, c.months[:], nil); err != nil {
		return nil, fmt.Errorf("%w: month: %s", ErrInvalidCron, err)
	}
	dowStarred, err := parseFieldStarred(fields[4], 0, 6, dowNames, c.dows[:])
	if err != nil {
		return nil, fmt.Errorf("%w: day-of-week: %s", ErrInvalidCron, err)
	}
	c.dowStarred = dowStarred

	return c, nil
}

func parseField(expr string, minVal, maxVal int, names map[string]int, mask []bool, _ *bool) error {
	_, err := parseFieldStarred(expr, minVal, maxVal, names, mask)
	return err
}

func parseFieldStarred(expr string, minVal, maxVal int, names map[string]int, mask []bool) (bool, error) {
	starred := false
	for _, part := range strings.Split(expr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return false, fmt.Errorf("empty term in %q", expr)
		}
		// Split out step.
		step := 1
		rangePart := part
		if idx := strings.Index(part, "/"); idx >= 0 {
			rangePart = part[:idx]
			stepStr := part[idx+1:]
			n, err := strconv.Atoi(stepStr)
			if err != nil || n < 1 {
				return false, fmt.Errorf("invalid step %q", stepStr)
			}
			step = n
		}
		// Parse range or single.
		lo, hi := minVal, maxVal
		if rangePart == "*" {
			starred = true
		} else if idx := strings.Index(rangePart, "-"); idx >= 0 {
			a, err := parseAtom(rangePart[:idx], minVal, maxVal, names)
			if err != nil {
				return false, err
			}
			b, err := parseAtom(rangePart[idx+1:], minVal, maxVal, names)
			if err != nil {
				return false, err
			}
			if a > b {
				return false, fmt.Errorf("range %d-%d is empty", a, b)
			}
			lo, hi = a, b
		} else {
			n, err := parseAtom(rangePart, minVal, maxVal, names)
			if err != nil {
				return false, err
			}
			lo, hi = n, n
		}
		// Stamp the mask.
		for v := lo; v <= hi; v += step {
			idx := v
			// DoW 7 normalises to 0 (POSIX cron treats 7 as Sunday).
			if maxVal == 6 && names != nil && v == 7 {
				idx = 0
			}
			if idx < 0 || idx >= len(mask) {
				return false, fmt.Errorf("value %d out of range %d-%d", idx, minVal, maxVal)
			}
			mask[idx] = true
		}
	}
	return starred, nil
}

func parseAtom(s string, minVal, maxVal int, names map[string]int) (int, error) {
	s = strings.TrimSpace(s)
	if names != nil {
		if v, ok := names[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q", s)
	}
	// Accept DoW 7 here too so `7` standalone (Sunday) is valid;
	// the caller's stamping loop normalises 7 → 0.
	if maxVal == 6 && names != nil && v == 7 {
		return v, nil
	}
	if v < minVal || v > maxVal {
		return 0, fmt.Errorf("value %d out of range %d-%d", v, minVal, maxVal)
	}
	return v, nil
}

// Next returns the next time at or strictly after `after` at which
// this schedule should fire. It rounds up to the next whole minute
// before searching, so consecutive Next() calls in a tight loop
// progress instead of looping on the same minute. The 4-year limit
// is a hard backstop against pathological expressions (e.g. day 31
// in months that don't have 31 days, with the wrong DoW) — real
// schedules resolve within at most one year.
func (c *CronSchedule) Next(after time.Time) (time.Time, error) {
	t := after.Add(time.Minute).Truncate(time.Minute)
	// 4 years = ~2.1M minutes; iterating per-field rather than
	// per-minute keeps the loop count well under 50k in the worst
	// realistic case.
	for iter := 0; iter < 4*366*24; iter++ {
		if !c.months[int(t.Month())] {
			t = startOfNextMonth(t)
			continue
		}
		if !c.matchesDay(t) {
			t = startOfNextDay(t)
			continue
		}
		if !c.hours[t.Hour()] {
			t = startOfNextHour(t)
			continue
		}
		if !c.minutes[t.Minute()] {
			t = t.Add(time.Minute)
			continue
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("%w: no match within 4 years from %s", ErrInvalidCron, after.Format(time.RFC3339))
}

// matchesDay applies POSIX cron's "OR semantics when both DoM and
// DoW are restricted" rule. With both fields starred, every day
// passes. With one starred, only the other applies. With both
// restricted, a day matches if it satisfies either constraint —
// classic gotcha for operators expecting AND.
func (c *CronSchedule) matchesDay(t time.Time) bool {
	dom := c.doms[t.Day()]
	dow := c.dows[int(t.Weekday())]
	switch {
	case c.domStarred && c.dowStarred:
		return true
	case c.domStarred:
		return dow
	case c.dowStarred:
		return dom
	default:
		return dom || dow
	}
}

func startOfNextMonth(t time.Time) time.Time {
	y, m := t.Year(), t.Month()
	m++
	if m > 12 {
		m = 1
		y++
	}
	return time.Date(y, m, 1, 0, 0, 0, 0, t.Location())
}

func startOfNextDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location()).AddDate(0, 0, 1)
}

func startOfNextHour(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location()).Add(time.Hour)
}
