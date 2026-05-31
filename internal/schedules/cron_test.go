// SPDX-License-Identifier: Apache-2.0

package schedules

import (
	"errors"
	"testing"
	"time"
)

func mustParse(t *testing.T, expr string) *CronSchedule {
	t.Helper()
	c, err := ParseCron(expr)
	if err != nil {
		t.Fatalf("ParseCron(%q): %v", expr, err)
	}
	return c
}

func TestParseCronWrongFieldCount(t *testing.T) {
	for _, expr := range []string{"", "0", "0 0", "0 0 0", "0 0 0 0", "0 0 0 0 0 0"} {
		if _, err := ParseCron(expr); !errors.Is(err, ErrInvalidCron) {
			t.Errorf("ParseCron(%q): expected ErrInvalidCron, got %v", expr, err)
		}
	}
}

func TestParseCronAtomVariants(t *testing.T) {
	tests := []struct {
		expr string
		ok   bool
	}{
		{"* * * * *", true},
		{"0 0 * * *", true},
		{"0 0 1 1 *", true},
		{"*/15 * * * *", true},
		{"0-30/5 * * * *", true},
		{"0,15,30,45 * * * *", true},
		{"0 0 * jan *", true},
		{"0 0 * * mon-fri", true},
		{"0 0 * * sun", true},
		{"0 0 * * 7", true},    // POSIX: 7 = Sunday
		{"60 * * * *", false},  // minute out of range
		{"* 24 * * *", false},  // hour out of range
		{"* * 32 * *", false},  // day out of range
		{"* * * 13 *", false},  // month out of range
		{"* * * * 8", false},   // dow out of range
		{"5-2 * * * *", false}, // empty range
		{"*/0 * * * *", false}, // zero step
		{"foo * * * *", false}, // garbage
		{"* * * foo *", false}, // garbage month
		{"* * * * foo", false}, // garbage dow
	}
	for _, tt := range tests {
		_, err := ParseCron(tt.expr)
		if tt.ok && err != nil {
			t.Errorf("ParseCron(%q): expected ok, got %v", tt.expr, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("ParseCron(%q): expected error, got nil", tt.expr)
		}
	}
}

func TestParseCronExprRoundTrip(t *testing.T) {
	c := mustParse(t, "0 3 * * *")
	if c.Expr() != "0 3 * * *" {
		t.Errorf("Expr() = %q, want %q", c.Expr(), "0 3 * * *")
	}
}

func TestNextDailyAt0300(t *testing.T) {
	c := mustParse(t, "0 3 * * *")
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	next, err := c.Next(now)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := time.Date(2026, 6, 1, 3, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %s, want %s", next, want)
	}
}

func TestNextSkipsToNextValidMinute(t *testing.T) {
	c := mustParse(t, "*/15 * * * *")
	now := time.Date(2026, 1, 1, 10, 7, 30, 0, time.UTC)
	next, err := c.Next(now)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := time.Date(2026, 1, 1, 10, 15, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %s, want %s", next, want)
	}
}

func TestNextSkipsToNextValidHour(t *testing.T) {
	// Only fire at 03:00 each day.
	c := mustParse(t, "0 3 * * *")
	now := time.Date(2026, 1, 1, 2, 59, 0, 0, time.UTC)
	next, err := c.Next(now)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %s, want %s", next, want)
	}
}

func TestNextRollsToNextMonthForMonthlyFirst(t *testing.T) {
	c := mustParse(t, "0 0 1 * *")
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	next, err := c.Next(now)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %s, want %s", next, want)
	}
}

func TestNextWeekdaysOnly(t *testing.T) {
	// Saturday → next match is Monday at 09:00.
	c := mustParse(t, "0 9 * * mon-fri")
	saturday := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	next, err := c.Next(saturday)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC) // Mon 2026-06-01
	if !next.Equal(want) {
		t.Errorf("Next = %s, want %s", next, want)
	}
}

func TestNextDoMOrDoWWhenBothRestricted(t *testing.T) {
	// POSIX: 1st of the month OR Friday — whichever comes first.
	c := mustParse(t, "0 0 1 * fri")
	// Wed 2026-01-28 → next Fri is 2026-01-30; 1st of next month
	// is 2026-02-01. Friday wins.
	now := time.Date(2026, 1, 28, 0, 0, 0, 0, time.UTC)
	next, err := c.Next(now)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := time.Date(2026, 1, 30, 0, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %s, want %s", next, want)
	}
}

func TestNextAdvancesPastCurrentMinute(t *testing.T) {
	// At exactly 03:00, Next must return tomorrow at 03:00.
	c := mustParse(t, "0 3 * * *")
	now := time.Date(2026, 1, 1, 3, 0, 0, 0, time.UTC)
	next, err := c.Next(now)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %s, want %s", next, want)
	}
}

func TestNextSundayAcceptsDoW7(t *testing.T) {
	c := mustParse(t, "0 0 * * 7")
	// Monday → next Sunday.
	monday := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) // 2026-06-01 = Monday
	next, err := c.Next(monday)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	want := time.Date(2026, 6, 7, 0, 0, 0, 0, time.UTC) // following Sunday
	if !next.Equal(want) {
		t.Errorf("Next = %s, want %s", next, want)
	}
}

func TestNextStepWithinRange(t *testing.T) {
	c := mustParse(t, "0-30/10 * * * *")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	want := []time.Time{
		time.Date(2026, 1, 1, 0, 10, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 20, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC),
		time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC),
	}
	for i, w := range want {
		got, err := c.Next(now)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if !got.Equal(w) {
			t.Errorf("iter %d: got %s, want %s", i, got, w)
		}
		now = got
	}
}

func TestNextHandlesFebruary29InNonLeapYear(t *testing.T) {
	// "Fire at midnight on Feb 29" — only valid in leap years.
	c := mustParse(t, "0 0 29 2 *")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) // 2026 not leap
	next, err := c.Next(now)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	// 2028 is the next leap year.
	want := time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Errorf("Next = %s, want %s", next, want)
	}
}

func TestNextRespectsLocation(t *testing.T) {
	// Local-time scheduling must not silently convert to UTC.
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tz database unavailable: %v", err)
	}
	c := mustParse(t, "0 9 * * *")
	now := time.Date(2026, 1, 1, 8, 30, 0, 0, loc)
	next, err := c.Next(now)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if next.Location() != loc {
		t.Errorf("Next location = %v, want %v", next.Location(), loc)
	}
	if next.Hour() != 9 {
		t.Errorf("Next hour = %d, want 9", next.Hour())
	}
}
