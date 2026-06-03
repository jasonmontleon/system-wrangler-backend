// SPDX-License-Identifier: Apache-2.0

package notifications

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestDeliveryModeIsValid(t *testing.T) {
	for _, m := range []DeliveryMode{ModeDashboard, ModeQuiet, ModeAlways} {
		if !m.IsValid() {
			t.Errorf("%q should be valid", m)
		}
	}
	if DeliveryMode("page").IsValid() {
		t.Error("unknown mode should be invalid")
	}
}

func TestModeFor(t *testing.T) {
	p := Policy{Severities: map[string]DeliveryMode{"info": ModeAlways}}
	if got := p.ModeFor("info"); got != ModeAlways {
		t.Errorf("explicit info = %q, want always", got)
	}
	// Falls back to the built-in default for an unset severity.
	if got := p.ModeFor("critical"); got != ModeAlways {
		t.Errorf("default critical = %q, want always", got)
	}
	if got := p.ModeFor("warning"); got != ModeQuiet {
		t.Errorf("default warning = %q, want quiet", got)
	}
	// Unknown severity falls back to quiet.
	if got := p.ModeFor("nope"); got != ModeQuiet {
		t.Errorf("unknown severity = %q, want quiet", got)
	}
	// An invalid stored mode is ignored in favor of the default.
	p2 := Policy{Severities: map[string]DeliveryMode{"warning": "bogus"}}
	if got := p2.ModeFor("warning"); got != ModeQuiet {
		t.Errorf("invalid stored mode = %q, want default quiet", got)
	}
}

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p.Timezone != "UTC" || len(p.Windows) != 0 {
		t.Errorf("default policy = %+v", p)
	}
	if p.Severities["info"] != ModeDashboard || p.Severities["critical"] != ModeAlways {
		t.Errorf("default severities = %+v", p.Severities)
	}
}

func TestPolicyValidate(t *testing.T) {
	tests := []struct {
		name    string
		in      Policy
		wantErr bool
	}{
		{"empty defaults tz to UTC", Policy{}, false},
		{"good window", Policy{Windows: []QuietWindow{{Days: []time.Weekday{time.Monday}, Start: "22:00", End: "08:00"}}}, false},
		{"bad timezone", Policy{Timezone: "Mars/Phobos"}, true},
		{"unknown severity key", Policy{Severities: map[string]DeliveryMode{"fatal": ModeAlways}}, true},
		{"invalid mode", Policy{Severities: map[string]DeliveryMode{"info": "page"}}, true},
		{"bad start time", Policy{Windows: []QuietWindow{{Start: "9am", End: "17:00"}}}, true},
		{"bad end time", Policy{Windows: []QuietWindow{{Start: "09:00", End: "25:30"}}}, true},
		{"equal start end", Policy{Windows: []QuietWindow{{Start: "09:00", End: "09:00"}}}, true},
		{"weekday out of range", Policy{Windows: []QuietWindow{{Days: []time.Weekday{7}, Start: "09:00", End: "17:00"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := tt.in
			err := in.Validate()
			if tt.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, ErrInvalid) {
				t.Errorf("want ErrInvalid, got %v", err)
			}
			if !tt.wantErr && in.Timezone == "" {
				t.Error("empty timezone should default to UTC")
			}
		})
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}

func TestInQuietHours(t *testing.T) {
	sameDay := Policy{Windows: []QuietWindow{{Days: []time.Weekday{time.Monday}, Start: "09:00", End: "17:00"}}}
	overnight := Policy{Windows: []QuietWindow{{Days: []time.Weekday{time.Friday}, Start: "22:00", End: "08:00"}}}
	allDay := Policy{Windows: []QuietWindow{{Start: "00:00", End: "24:00"}}}
	tz := Policy{Timezone: "America/New_York", Windows: []QuietWindow{{Start: "09:00", End: "17:00"}}}

	tests := []struct {
		name string
		p    Policy
		at   string // RFC3339
		want bool
	}{
		{"no windows never quiet", Policy{}, "2026-06-01T03:00:00Z", false},
		{"same-day inside", sameDay, "2026-06-01T12:00:00Z", true}, // Mon
		{"same-day before", sameDay, "2026-06-01T08:00:00Z", false},
		{"same-day wrong weekday", sameDay, "2026-06-02T12:00:00Z", false},      // Tue
		{"overnight evening", overnight, "2026-06-05T23:00:00Z", true},          // Fri 23:00
		{"overnight morning next day", overnight, "2026-06-06T02:00:00Z", true}, // Sat 02:00 (Fri night)
		{"overnight cleared", overnight, "2026-06-06T09:00:00Z", false},         // Sat 09:00
		{"overnight wrong evening", overnight, "2026-06-06T23:00:00Z", false},   // Sat 23:00
		{"all-day true", allDay, "2026-06-03T15:30:00Z", true},
		{"tz inside (10:00 EDT)", tz, "2026-06-01T14:00:00Z", true},
		{"tz outside (21:00 prev EDT)", tz, "2026-06-01T01:00:00Z", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.InQuietHours(mustTime(t, tt.at)); got != tt.want {
				t.Errorf("InQuietHours = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInQuietHoursBadTimezoneFallsBackToUTC(t *testing.T) {
	// An invalid stored timezone must not panic — it falls back to UTC.
	p := Policy{Timezone: "Nowhere/Land", Windows: []QuietWindow{{Start: "00:00", End: "24:00"}}}
	if !p.InQuietHours(mustTime(t, "2026-06-01T12:00:00Z")) {
		t.Error("all-day window should match even with a bad tz (UTC fallback)")
	}
}

func TestParseHHMM(t *testing.T) {
	ok := map[string]int{"00:00": 0, "09:30": 570, "24:00": 1440, "23:59": 1439}
	for s, want := range ok {
		if got, err := parseHHMM(s); err != nil || got != want {
			t.Errorf("parseHHMM(%q) = %d,%v want %d", s, got, err, want)
		}
	}
	for _, bad := range []string{"", "9", "9:00:00", "ab:cd", "24:01", "12:60", "-1:00"} {
		if _, err := parseHHMM(bad); err == nil {
			t.Errorf("parseHHMM(%q) should error", bad)
		}
	}
}

// --- store: policy + pending ---

func TestGetPolicyDefaultThenRoundTrip(t *testing.T) {
	st := newTestStore(t)
	p, err := st.GetPolicy()
	if err != nil {
		t.Fatalf("get default: %v", err)
	}
	if p.Timezone != "UTC" || len(p.Windows) != 0 || p.Severities["info"] != ModeDashboard {
		t.Errorf("default policy = %+v", p)
	}

	in := Policy{
		Timezone:   "America/New_York",
		Windows:    []QuietWindow{{Days: []time.Weekday{time.Saturday, time.Sunday}, Start: "00:00", End: "24:00"}},
		Severities: map[string]DeliveryMode{"warning": ModeAlways},
	}
	if err := st.SetPolicy(in); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := st.GetPolicy()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Timezone != "America/New_York" || len(got.Windows) != 1 {
		t.Errorf("policy not persisted: %+v", got)
	}
	if !reflect.DeepEqual(got.Windows[0].Days, []time.Weekday{time.Saturday, time.Sunday}) {
		t.Errorf("days = %v", got.Windows[0].Days)
	}
	if got.Severities["warning"] != ModeAlways {
		t.Errorf("severity not persisted: %+v", got.Severities)
	}
	// Upsert replaces.
	if err := st.SetPolicy(Policy{Timezone: "UTC"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _ = st.GetPolicy()
	if got.Timezone != "UTC" || len(got.Windows) != 0 {
		t.Errorf("upsert did not replace: %+v", got)
	}
}

func TestSetPolicyRejectsInvalid(t *testing.T) {
	st := newTestStore(t)
	if err := st.SetPolicy(Policy{Timezone: "Bad/Zone"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid policy should be ErrInvalid, got %v", err)
	}
}

func TestPendingEnqueueListDelete(t *testing.T) {
	st := newTestStore(t)
	a, err := st.EnqueuePending(PendingDelivery{
		RuleID: "r1", RuleName: "Disk", SystemID: "s1", Severity: "warning", Kind: "fired",
		Message: Message{Subject: "x", Kind: "fired", RuleName: "Disk", SystemID: "s1"},
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if a.ID == "" || a.EnqueuedAt.IsZero() {
		t.Errorf("enqueue did not fill id/time: %+v", a)
	}
	_, _ = st.EnqueuePending(PendingDelivery{RuleID: "r1", SystemID: "s1", Kind: "resolved", Message: Message{Kind: "resolved"}})

	list, err := st.ListPending()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].Message.Subject != "x" {
		t.Errorf("message not round-tripped: %+v", list[0].Message)
	}

	if err := st.DeletePending(nil); err != nil {
		t.Errorf("delete empty should be no-op: %v", err)
	}
	if err := st.DeletePending([]string{list[0].ID, list[1].ID}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	list, _ = st.ListPending()
	if len(list) != 0 {
		t.Errorf("after delete len = %d, want 0", len(list))
	}
}

func TestPolicyPendingStoreDBErrors(t *testing.T) {
	st := newTestStore(t)
	_ = st.db.Close()
	if _, err := st.GetPolicy(); err == nil {
		t.Error("GetPolicy on closed db should error")
	}
	if err := st.SetPolicy(Policy{Timezone: "UTC"}); err == nil {
		t.Error("SetPolicy on closed db should error")
	}
	if _, err := st.EnqueuePending(PendingDelivery{RuleID: "r"}); err == nil {
		t.Error("EnqueuePending on closed db should error")
	}
	if _, err := st.ListPending(); err == nil {
		t.Error("ListPending on closed db should error")
	}
	if err := st.DeletePending([]string{"x"}); err == nil {
		t.Error("DeletePending on closed db should error")
	}
}
