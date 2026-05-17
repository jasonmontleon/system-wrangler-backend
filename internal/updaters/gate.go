// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"sync"
)

// Gate is a FIFO concurrency limiter with a dynamic ceiling. The
// Runner acquires a slot before each check / apply ansible call so
// "Check the fleet" fan-outs don't spawn an unbounded number of
// playbook processes; extras queue in arrival order and start as
// in-flight runs Release.
//
// Limit is re-read on every admission decision, so a settings change
// takes effect against the next waiter — in-flight holders keep
// their slot. When the operator lowers the limit, no new acquirers
// admit until enough Releases bring active below the new ceiling.
type Gate struct {
	// Limit returns the current ceiling. A nil Limit or a return
	// value below 1 falls back to defaultLimit so a misconfigured
	// gate doesn't wedge the runner.
	Limit func() int

	mu      sync.Mutex
	active  int
	waiters []chan struct{}
}

// defaultLimit is the silent fallback when Limit is nil or returns a
// non-positive number. Picked to match settings.DefaultUpdateConcurrencyLimit
// without creating an import cycle.
const defaultLimit = 4

func (g *Gate) limit() int {
	if g == nil || g.Limit == nil {
		return defaultLimit
	}
	n := g.Limit()
	if n < 1 {
		return defaultLimit
	}
	return n
}

// Acquire blocks until a slot is free, then returns nil. If ctx is
// cancelled while the caller is queued, Acquire returns ctx.Err()
// and leaves the active count untouched. If the caller is signaled
// (slot already handed off) and ctx is cancelled at the same
// instant, the slot is forwarded to the next waiter so no slot
// leaks.
func (g *Gate) Acquire(ctx context.Context) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.active < g.limit() {
		g.active++
		g.mu.Unlock()
		return nil
	}
	ch := make(chan struct{})
	g.waiters = append(g.waiters, ch)
	g.mu.Unlock()

	select {
	case <-ch:
		// Slot was handed off to us under the lock; active was
		// already incremented by the releaser.
		return nil
	case <-ctx.Done():
		g.mu.Lock()
		defer g.mu.Unlock()
		// Try to dequeue ourselves. If found, the slot was never
		// granted and there's nothing to release.
		for i, w := range g.waiters {
			if w == ch {
				g.waiters = append(g.waiters[:i], g.waiters[i+1:]...)
				return ctx.Err()
			}
		}
		// Not in the queue → we were signaled. The releaser already
		// incremented active for us, so we must Release the slot to
		// pass it along to the next waiter.
		g.releaseLocked()
		return ctx.Err()
	}
}

// Release returns a slot to the pool. It is safe to call Release
// without a matching Acquire return only when Acquire returned nil;
// callers that received ctx.Err() must not Release.
func (g *Gate) Release() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.releaseLocked()
}

func (g *Gate) releaseLocked() {
	if g.active > 0 {
		g.active--
	}
	// Hand off slots to waiters while we're still under capacity.
	// A drop in limit() means we may release without admitting the
	// next waiter — that's the intended behavior; the queue keeps
	// its position and admission resumes on the next Release.
	for len(g.waiters) > 0 && g.active < g.limit() {
		next := g.waiters[0]
		g.waiters = g.waiters[1:]
		g.active++
		close(next)
	}
}

// Active is the number of slots currently held. Exposed for tests
// and future metrics.
func (g *Gate) Active() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.active
}

// Waiting is the depth of the FIFO queue. Exposed for tests and
// future metrics.
func (g *Gate) Waiting() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.waiters)
}
