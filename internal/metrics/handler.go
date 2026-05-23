// SPDX-License-Identifier: Apache-2.0

// Package metrics is the thin authenticated proxy that lets the SPA
// talk to Prometheus. Prometheus binds container-local only;
// everything goes through here so the same session + scope checks
// apply to dashboard queries as to inventory reads. Design and
// discipline: research/metrics-pipeline.md.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"system-wrangler-backend/internal/router"
)

// Handler exposes /api/metrics/query and /api/metrics/query_range as
// session-authenticated forwarders. The body shape returned is
// Prometheus's JSON HTTP API verbatim — clients deserialize it
// directly, and we don't transform the response.
type Handler struct {
	// UpstreamURL is the base URL Prometheus listens on, e.g.
	// "http://prometheus:9090". Trailing slash is tolerated.
	UpstreamURL string
	// Client is the HTTP client used to talk to Prometheus. nil
	// falls back to a default 30s-timeout client.
	Client *http.Client

	// CanRead gates both endpoints. Bound to "any authenticated
	// user" in main.go, since metrics visibility tracks the system
	// visibility that's already RBAC-checked on /api/systems.
	// Tightening this to "Operator+" or scope-filtering by visible
	// systems is a v2 concern — the label set on the Prometheus
	// side already includes system_id so an authorised dashboard
	// already filters.
	CanRead func(ctx context.Context) bool
}

// Register attaches both routes behind mw (the authenticated-user
// middleware).
func (h *Handler) Register(mux router.Mux, mw func(http.Handler) http.Handler) {
	if mw == nil {
		mw = func(next http.Handler) http.Handler { return next }
	}
	mux.Handle("GET /api/metrics/query", mw(http.HandlerFunc(h.query)))
	mux.Handle("POST /api/metrics/query", mw(http.HandlerFunc(h.query)))
	mux.Handle("GET /api/metrics/query_range", mw(http.HandlerFunc(h.queryRange)))
	mux.Handle("POST /api/metrics/query_range", mw(http.HandlerFunc(h.queryRange)))
}

func (h *Handler) query(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, "/api/v1/query")
}

func (h *Handler) queryRange(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, "/api/v1/query_range")
}

func (h *Handler) forward(w http.ResponseWriter, r *http.Request, upstreamPath string) {
	if h.UpstreamURL == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "metrics pipeline not configured")
		return
	}
	if h.CanRead != nil && !h.CanRead(r.Context()) {
		writeJSONError(w, http.StatusForbidden, "forbidden")
		return
	}
	base := strings.TrimRight(h.UpstreamURL, "/")
	upstream, err := url.Parse(base + upstreamPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "invalid upstream URL")
		return
	}

	// Carry the query params from GET; for POST we forward the form
	// body verbatim. Prometheus accepts both forms.
	upstream.RawQuery = r.URL.RawQuery
	var body io.Reader
	if r.Method == http.MethodPost {
		body = r.Body
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream.String(), body)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "build upstream request: "+err.Error())
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("Accept", "application/json")

	// Upstream URL is operator-controlled via SW_PROMETHEUS_URL; the
	// request URL is the operator's prefix + a fixed path. User
	// input only contributes to the query string, which is what
	// makes this a passthrough proxy. G704 is a false positive.
	resp, err := h.client().Do(req) //nolint:gosec
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			writeJSONError(w, http.StatusGatewayTimeout, "upstream timed out")
			return
		}
		writeJSONError(w, http.StatusBadGateway, "upstream error: "+err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		// The status code is already written; just log and move on.
		slog.Warn("metrics: copy response", "err", err)
	}
}

func (h *Handler) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// msg is a backend-constructed string, never user input. The
	// %q verb JSON-escapes embedded quotes/control chars so the
	// resulting JSON is always well-formed.
	_, _ = fmt.Fprintf(w, `{"status":"error","errorType":"upstream","error":%q}`, msg) //nolint:gosec
}
