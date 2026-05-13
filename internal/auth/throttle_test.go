// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestThrottleAllowsUntilMax(t *testing.T) {
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	th := NewThrottle(time.Minute, 3, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if w := th.Check("1.2.3.4"); w != 0 {
			t.Fatalf("attempt %d: wait = %v, want 0", i, w)
		}
		th.Record("1.2.3.4")
	}
	w := th.Check("1.2.3.4")
	if w <= 0 {
		t.Errorf("after max records, wait = %v, want > 0", w)
	}
	if w > time.Minute {
		t.Errorf("wait = %v, want <= window", w)
	}
}

func TestThrottlePerKey(t *testing.T) {
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	th := NewThrottle(time.Minute, 2, func() time.Time { return now })
	th.Record("a")
	th.Record("a")
	if w := th.Check("a"); w == 0 {
		t.Error("key a should be blocked")
	}
	if w := th.Check("b"); w != 0 {
		t.Errorf("key b wait = %v, want 0", w)
	}
}

func TestThrottlePrunesAfterWindow(t *testing.T) {
	now := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	clock := now
	th := NewThrottle(time.Minute, 2, func() time.Time { return clock })
	th.Record("k")
	th.Record("k")
	if w := th.Check("k"); w == 0 {
		t.Fatal("expected throttled")
	}
	clock = clock.Add(2 * time.Minute)
	if w := th.Check("k"); w != 0 {
		t.Errorf("after window, wait = %v, want 0", w)
	}
}

func TestThrottleNilSafe(t *testing.T) {
	var th *Throttle
	if w := th.Check("k"); w != 0 {
		t.Errorf("nil throttle Check = %v, want 0", w)
	}
	th.Record("k")
}

func TestClientIPStripsPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.5:54321"
	if got := clientIP(r); got != "10.0.0.5" {
		t.Errorf("clientIP = %q, want 10.0.0.5", got)
	}
}

func TestClientIPIPv6(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[::1]:54321"
	if got := clientIP(r); got != "::1" {
		t.Errorf("clientIP = %q, want ::1", got)
	}
}

func TestLockDurationBelowThreshold(t *testing.T) {
	for i := 0; i < LockoutThreshold; i++ {
		if d := lockDuration(i); d != 0 {
			t.Errorf("attempts %d: duration = %v, want 0", i, d)
		}
	}
}

func TestLockDurationGrowsThenCaps(t *testing.T) {
	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{LockoutThreshold, 1 * time.Minute},
		{LockoutThreshold + 1, 2 * time.Minute},
		{LockoutThreshold + 2, 4 * time.Minute},
		{LockoutThreshold + 3, 8 * time.Minute},
		{LockoutThreshold + 4, LockoutMaxDuration},
		{LockoutThreshold + 100, LockoutMaxDuration},
	}
	for _, c := range cases {
		if got := lockDuration(c.attempts); got != c.want {
			t.Errorf("attempts %d: duration = %v, want %v", c.attempts, got, c.want)
		}
	}
}
