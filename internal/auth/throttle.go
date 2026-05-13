// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net"
	"net/http"
	"sync"
	"time"

	"system-wrangler-backend/internal/audit"
)

// Throttle is an in-memory sliding-window counter keyed by an arbitrary
// string (typically a client IP). The login and TOTP-verify handlers
// record failures here so a single source spraying credentials across
// many usernames trips a 429 before the per-account lockout can be
// circumvented by rotating victims. Lost on restart by design — process
// memory is the right tier for this counter; persisting it would be
// noise.
type Throttle struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	events map[string][]time.Time
	now    func() time.Time
}

// NewThrottle returns a Throttle that allows up to limit events per key
// within the rolling window. now defaults to time.Now when nil.
func NewThrottle(window time.Duration, limit int, now func() time.Time) *Throttle {
	if now == nil {
		now = time.Now
	}
	return &Throttle{
		window: window,
		max:    limit,
		events: map[string][]time.Time{},
		now:    now,
	}
}

// Check reports how long the caller must wait before the key is allowed
// again. Zero means the key is currently allowed. Stale events (outside
// the window) are pruned as a side effect so memory doesn't grow
// unbounded.
func (t *Throttle) Check(key string) time.Duration {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(key)
	if len(t.events[key]) < t.max {
		return 0
	}
	oldest := t.events[key][0]
	wait := oldest.Add(t.window).Sub(t.now())
	if wait < 0 {
		return 0
	}
	return wait
}

// Record appends a failure timestamp for key. Bucket pruning runs first
// so a record never carries forward expired entries.
func (t *Throttle) Record(key string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(key)
	t.events[key] = append(t.events[key], t.now())
}

func (t *Throttle) prune(key string) {
	cutoff := t.now().Add(-t.window)
	ev := t.events[key]
	i := 0
	for i < len(ev) && ev[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		ev = ev[i:]
	}
	if len(ev) == 0 {
		delete(t.events, key)
		return
	}
	t.events[key] = ev
}

// clientIP returns the host portion of the request's remote address.
// Prefers the audit-context value (set by the request-meta middleware)
// since that's already canonicalized; falls back to r.RemoteAddr when
// the middleware wasn't on the chain. The port is stripped so a single
// client across many ephemeral source ports collapses to one bucket.
func clientIP(r *http.Request) string {
	addr := audit.RemoteAddrFromContext(r.Context())
	if addr == "" {
		addr = r.RemoteAddr
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
