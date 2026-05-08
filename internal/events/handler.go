// SPDX-License-Identifier: Apache-2.0

package events

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// keepaliveInterval is how often the SSE handler emits a comment line to
// stop intermediaries from severing an idle connection.
const keepaliveInterval = 20 * time.Second

// SSEHandler streams hub events to the client as text/event-stream.
// The connection terminates when the request context is cancelled
// (browser disconnect or server shutdown).
func SSEHandler(hub *Hub) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		// X-Accel-Buffering disables nginx response buffering when proxied;
		// harmless when not behind nginx.
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		sub := hub.Subscribe()
		defer hub.Unsubscribe(sub)

		keepalive := time.NewTicker(keepaliveInterval)
		defer keepalive.Stop()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-sub.Ch:
				if !ok {
					return
				}
				payload, err := json.Marshal(e)
				if err != nil {
					continue
				}
				if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
					return
				}
				flusher.Flush()
			case <-keepalive.C:
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})
}
