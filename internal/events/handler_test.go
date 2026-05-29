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

func TestSSEHandlerTerminatesOnHubClose(t *testing.T) {
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

	// Wait until the handler has subscribed before closing the hub, otherwise
	// the close races the subscribe and the handler may never see it.
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

	hub.Close()

	// The handler should return promptly once its subscriber channel closes,
	// dropping the subscriber count back to zero.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hub.mu.RLock()
		n := len(hub.subscribers)
		hub.mu.RUnlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("handler did not return after Hub.Close")
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

func TestSSEHandlerEmitsKeepaliveComment(t *testing.T) {
	hub := NewHub(quietLogger())
	defer hub.Close()
	srv := httptest.NewServer(sseHandler(hub, 25*time.Millisecond))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	buf := make([]byte, 256)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _ := resp.Body.Read(buf)
		if n > 0 && bytesContainsKeepalive(buf[:n]) {
			return
		}
	}
	t.Error("keepalive comment not received within 2s")
}

func bytesContainsKeepalive(b []byte) bool {
	return string(b) != "" && (string(b) == ": keepalive\n\n" || contains(b, []byte(": keepalive")))
}

func contains(haystack, needle []byte) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

type nonFlusher struct {
	header http.Header
	code   int
	buf    []byte
}

func (n *nonFlusher) Header() http.Header {
	if n.header == nil {
		n.header = http.Header{}
	}
	return n.header
}
func (n *nonFlusher) Write(p []byte) (int, error) { n.buf = append(n.buf, p...); return len(p), nil }
func (n *nonFlusher) WriteHeader(code int)        { n.code = code }

func TestSSEHandlerRejectsNonFlusher(t *testing.T) {
	hub := NewHub(quietLogger())
	defer hub.Close()
	w := &nonFlusher{}
	req := httptestReq(t)
	SSEHandler(hub).ServeHTTP(w, req)
	if w.code != http.StatusInternalServerError {
		t.Errorf("code = %d, want 500", w.code)
	}
}

func httptestReq(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/events", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}
