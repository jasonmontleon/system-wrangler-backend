// SPDX-License-Identifier: Apache-2.0

// Package events fans out small notifications ("doorbells") from the
// backend to subscribed SSE clients. Events carry a type, not data —
// clients re-fetch the affected REST endpoint on receipt.
package events

import (
	"log/slog"
	"sync"
)

// Event is the broadcast payload. Keep it small.
type Event struct {
	Type string `json:"type"`
}

// Hub fans out events to current subscribers. Safe for concurrent use.
// Slow subscribers drop events instead of blocking the publisher.
type Hub struct {
	mu          sync.RWMutex
	subscribers map[*Subscriber]struct{}
	logger      *slog.Logger
}

// NewHub constructs an empty Hub. A nil logger is replaced with slog.Default.
func NewHub(logger *slog.Logger) *Hub {
	if logger == nil {
		logger = slog.Default()
	}
	return &Hub{
		subscribers: map[*Subscriber]struct{}{},
		logger:      logger,
	}
}

// Subscriber is an event sink. Owners must Unsubscribe before exiting.
type Subscriber struct {
	Ch chan Event
}

// Subscribe registers and returns a new Subscriber with a buffered channel.
// Callers MUST Unsubscribe before discarding the returned subscriber.
func (h *Hub) Subscribe() *Subscriber {
	s := &Subscriber{Ch: make(chan Event, 16)}
	h.mu.Lock()
	h.subscribers[s] = struct{}{}
	h.mu.Unlock()
	return s
}

// Unsubscribe removes s from the hub and closes its channel. Idempotent.
func (h *Hub) Unsubscribe(s *Subscriber) {
	h.mu.Lock()
	if _, ok := h.subscribers[s]; ok {
		delete(h.subscribers, s)
		close(s.Ch)
	}
	h.mu.Unlock()
}

// Broadcast sends e to every subscriber via a non-blocking send. A slow
// subscriber whose buffer is full misses the event rather than backing
// up the publisher; the SPA will catch up on its next refetch anyway.
func (h *Hub) Broadcast(e Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for s := range h.subscribers {
		select {
		case s.Ch <- e:
		default:
			h.logger.Warn("event dropped: subscriber slow", "type", e.Type)
		}
	}
}
