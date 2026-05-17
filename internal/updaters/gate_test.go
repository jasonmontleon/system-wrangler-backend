// SPDX-License-Identifier: Apache-2.0

package updaters

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGateNilSafe(t *testing.T) {
	var g *Gate
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("nil Acquire returned %v", err)
	}
	g.Release()
	if g.Active() != 0 || g.Waiting() != 0 {
		t.Fatalf("nil counts: active=%d waiting=%d", g.Active(), g.Waiting())
	}
}

func TestGateAdmitsUpToLimit(t *testing.T) {
	g := &Gate{Limit: func() int { return 3 }}
	for i := 0; i < 3; i++ {
		if err := g.Acquire(context.Background()); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	if g.Active() != 3 {
		t.Fatalf("active = %d, want 3", g.Active())
	}
	if g.Waiting() != 0 {
		t.Fatalf("waiting = %d, want 0", g.Waiting())
	}
}

func TestGateQueuesOverflow(t *testing.T) {
	g := &Gate{Limit: func() int { return 1 }}
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	admitted := make(chan int, 3)
	for i := 0; i < 3; i++ {
		go func(id int) {
			if err := g.Acquire(context.Background()); err != nil {
				return
			}
			admitted <- id
		}(i)
	}
	// Give the goroutines time to queue.
	waitForWaiters(t, g, 3, time.Second)
	if g.Active() != 1 {
		t.Fatalf("active before release = %d, want 1", g.Active())
	}
	g.Release()
	first := <-admitted
	if first < 0 || first > 2 {
		t.Fatalf("unexpected admitted id: %d", first)
	}
	// Two waiters still queued; we still hold one slot.
	if g.Waiting() != 2 {
		t.Fatalf("waiting after first release = %d, want 2", g.Waiting())
	}
	g.Release()
	<-admitted
	g.Release()
	<-admitted
}

func TestGateAdmitsInFIFOOrder(t *testing.T) {
	g := &Gate{Limit: func() int { return 1 }}
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("initial acquire: %v", err)
	}
	const n = 5
	startOrder := make(chan int, n)
	for i := 0; i < n; i++ {
		// Sequentially enqueue waiters under the lock so we can
		// assert deterministic FIFO admission.
		ready := make(chan struct{})
		go func(id int) {
			close(ready)
			if err := g.Acquire(context.Background()); err == nil {
				startOrder <- id
			}
		}(i)
		<-ready
		waitForWaiters(t, g, i+1, time.Second)
	}
	for i := 0; i < n; i++ {
		g.Release()
		got := <-startOrder
		if got != i {
			t.Fatalf("admission %d: got id %d, want %d", i, got, i)
		}
	}
}

func TestGateCtxCancelInQueue(t *testing.T) {
	g := &Gate{Limit: func() int { return 1 }}
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- g.Acquire(ctx)
	}()
	waitForWaiters(t, g, 1, time.Second)
	cancel()
	if err := <-done; err == nil {
		t.Fatal("acquire returned nil after cancel")
	}
	if g.Waiting() != 0 {
		t.Fatalf("waiting after cancel = %d, want 0", g.Waiting())
	}
	// The cancelled waiter must not have leaked its slot.
	if g.Active() != 1 {
		t.Fatalf("active after cancel = %d, want 1", g.Active())
	}
}

func TestGateDynamicLimitTakesEffect(t *testing.T) {
	limit := int64(1)
	g := &Gate{Limit: func() int { return int(atomic.LoadInt64(&limit)) }}
	if err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	// Raising the limit should admit a queued waiter on the next
	// Release (or via a no-op Release that triggers admission).
	admitted := make(chan struct{}, 1)
	go func() {
		if err := g.Acquire(context.Background()); err == nil {
			admitted <- struct{}{}
		}
	}()
	waitForWaiters(t, g, 1, time.Second)
	atomic.StoreInt64(&limit, 2)
	// A subsequent Release should both decrement active and admit
	// the waiter because the new ceiling is 2. We invoke Release on
	// the first holder.
	g.Release()
	select {
	case <-admitted:
	case <-time.After(time.Second):
		t.Fatal("waiter not admitted after limit raised")
	}
}

func TestGateLowerLimitDoesNotKickInflight(t *testing.T) {
	limit := int64(3)
	g := &Gate{Limit: func() int { return int(atomic.LoadInt64(&limit)) }}
	for i := 0; i < 3; i++ {
		if err := g.Acquire(context.Background()); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	// Lowering the limit while three holders are in flight is fine
	// — Active stays at 3, no panic, no leak.
	atomic.StoreInt64(&limit, 1)
	if g.Active() != 3 {
		t.Fatalf("active after lower = %d, want 3 (in-flight protected)", g.Active())
	}
	// A new acquirer should queue because active (3) >= limit (1).
	queued := make(chan struct{}, 1)
	go func() {
		if err := g.Acquire(context.Background()); err == nil {
			queued <- struct{}{}
		}
	}()
	waitForWaiters(t, g, 1, time.Second)
	// Releasing one holder leaves active=2, still above limit=1, so
	// the waiter stays queued.
	g.Release()
	if !stillQueued(g, 1, 100*time.Millisecond) {
		t.Fatal("waiter admitted prematurely under lowered limit")
	}
	g.Release()
	if !stillQueued(g, 1, 100*time.Millisecond) {
		t.Fatal("waiter admitted while active still equals lowered limit")
	}
	g.Release()
	select {
	case <-queued:
	case <-time.After(time.Second):
		t.Fatal("waiter never admitted after active dropped below limit")
	}
}

func TestGateConcurrentSoak(t *testing.T) {
	g := &Gate{Limit: func() int { return 5 }}
	var wg sync.WaitGroup
	var peak int64
	var current int64
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := g.Acquire(context.Background()); err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			n := atomic.AddInt64(&current, 1)
			for {
				p := atomic.LoadInt64(&peak)
				if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			atomic.AddInt64(&current, -1)
			g.Release()
		}()
	}
	wg.Wait()
	if peak > 5 {
		t.Fatalf("observed concurrent holders = %d, exceeded limit 5", peak)
	}
}

func waitForWaiters(t *testing.T, g *Gate, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if g.Waiting() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("Gate.Waiting()=%d, want %d", g.Waiting(), want)
}

func stillQueued(g *Gate, want int, dur time.Duration) bool {
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		if g.Waiting() != want {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return g.Waiting() == want
}
