// SPDX-License-Identifier: AGPL-3.0-or-later

package events

import (
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHubBroadcastDelivers(t *testing.T) {
	h := NewHub(quietLogger())
	a := h.Subscribe()
	b := h.Subscribe()
	defer h.Unsubscribe(a)
	defer h.Unsubscribe(b)

	h.Broadcast(Event{Type: "x"})

	for _, sub := range []*Subscriber{a, b} {
		select {
		case e := <-sub.Ch:
			if e.Type != "x" {
				t.Errorf("got Type=%q, want x", e.Type)
			}
		case <-time.After(time.Second):
			t.Error("timed out waiting for event")
		}
	}
}

func TestHubUnsubscribeStopsDelivery(t *testing.T) {
	h := NewHub(quietLogger())
	s := h.Subscribe()

	h.Unsubscribe(s)

	// Channel must be closed; receive returns zero value with ok=false.
	select {
	case _, ok := <-s.Ch:
		if ok {
			t.Error("channel should be closed after Unsubscribe")
		}
	case <-time.After(time.Second):
		t.Error("timed out waiting for channel close")
	}

	// Broadcast after Unsubscribe is harmless (sub is no longer in the map).
	h.Broadcast(Event{Type: "x"})
}

func TestHubSlowSubscriberDoesNotBlockPublisher(t *testing.T) {
	h := NewHub(quietLogger())
	slow := h.Subscribe()
	defer h.Unsubscribe(slow)

	// Fill the subscriber's buffer (16) and overflow it without ever draining.
	// Broadcast must return promptly via the non-blocking send.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			h.Broadcast(Event{Type: "x"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Broadcast blocked on a slow subscriber")
	}
}

func TestHubConcurrentSubscribeAndBroadcast(t *testing.T) {
	// Race-detector smoke test.
	h := NewHub(quietLogger())
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			s := h.Subscribe()
			h.Broadcast(Event{Type: "x"})
			// Drain so we don't fill the buffer.
			select {
			case <-s.Ch:
			case <-time.After(time.Second):
			}
			h.Unsubscribe(s)
		}()
	}
	wg.Wait()
}
