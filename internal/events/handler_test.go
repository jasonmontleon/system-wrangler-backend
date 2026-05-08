// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// readUntil reads lines from r until predicate returns true or the deadline
// passes. Returns the text accumulated.
func readUntil(t *testing.T, r *bufio.Reader, deadline time.Time, predicate func(string) bool) string {
	t.Helper()
	var sb strings.Builder
	for time.Now().Before(deadline) {
		line, err := r.ReadString('\n')
		if line != "" {
			sb.WriteString(line)
			if predicate(sb.String()) {
				return sb.String()
			}
		}
		if err != nil {
			return sb.String()
		}
	}
	return sb.String()
}

func TestSSEHandlerStreamsEvents(t *testing.T) {
	hub := NewHub(quietLogger())
	srv := httptest.NewServer(SSEHandler(hub))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", got)
	}

	// Wait for the handler to subscribe before broadcasting.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		hub.mu.RLock()
		n := len(hub.subscribers)
		hub.mu.RUnlock()
		if n == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	hub.Broadcast(Event{Type: "systems.changed"})

	got := readUntil(t, bufio.NewReader(resp.Body), time.Now().Add(2*time.Second),
		func(s string) bool { return strings.Contains(s, "systems.changed") })
	if !strings.Contains(got, `"type":"systems.changed"`) {
		t.Errorf("stream output = %q, want containing systems.changed event", got)
	}
}

func TestSSEHandlerTerminatesOnContextCancel(t *testing.T) {
	hub := NewHub(quietLogger())
	srv := httptest.NewServer(SSEHandler(hub))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	cancel()

	// After cancel, the body should reach EOF.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hub.mu.RLock()
		n := len(hub.subscribers)
		hub.mu.RUnlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("subscriber not removed after context cancel")
}
