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

// DefaultUpstreamURL is the Prometheus base URL the proxy uses when
// SW_PROMETHEUS_URL isn't set. Loopback assumes Prometheus shares
// the backend's network namespace; operators on the legacy
// two-container layout override with SW_PROMETHEUS_URL=http://prometheus:9090.
const DefaultUpstreamURL = "http://127.0.0.1:9090"

// maxQueryBodyBytes caps the request body parsed on the POST form path. A
// PromQL query — even an enforced one across many system_ids — is well
// under this; the cap exists to bound ParseForm's memory use.
const maxQueryBodyBytes = 1 << 20 // 1 MiB

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

	// AllowedSystems gates both endpoints and supplies the scope for
	// query rewriting. It returns:
	//   - all: the caller may read every system's metrics (any global
	//     role); the query is forwarded unchanged.
	//   - ids: when all is false, the exact set of system_ids the
	//     caller may read; every selector in the query is constrained
	//     to these (see enforceSystemID). An empty set short-circuits
	//     to an empty result without touching Prometheus.
	//   - ok: false when the request carries no resolvable scope, or
	//     scope resolution failed — the endpoint responds 403 (fail
	//     closed). nil leaves both endpoints open (used by tests).
	AllowedSystems func(ctx context.Context) (all bool, ids []string, ok bool)
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
	h.forward(w, r, "/api/v1/query", "vector")
}

func (h *Handler) queryRange(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, "/api/v1/query_range", "matrix")
}

// forward proxies one query to Prometheus after constraining it to the
// caller's visible systems. emptyResultType ("vector"|"matrix") is the
// resultType returned when the caller can see no systems, so the SPA gets
// a well-formed empty response without a request reaching Prometheus.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, upstreamPath, emptyResultType string) {
	if h.UpstreamURL == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "metrics pipeline not configured")
		return
	}
	all := true
	var ids []string
	if h.AllowedSystems != nil {
		var ok bool
		all, ids, ok = h.AllowedSystems(r.Context())
		if !ok {
			writeJSONError(w, http.StatusForbidden, "forbidden")
			return
		}
	}

	// ParseForm merges the URL query (GET) and an x-www-form-urlencoded
	// body (POST), so the rest of the handler is method-agnostic. Cap the
	// body first: a PromQL query is small, and an unbounded ParseForm on a
	// POST body is a memory-exhaustion vector.
	r.Body = http.MaxBytesReader(w, r.Body, maxQueryBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request parameters")
		return
	}
	params := r.Form
	q := params.Get("query")
	if strings.TrimSpace(q) == "" {
		writeJSONError(w, http.StatusBadRequest, "missing query parameter")
		return
	}

	if !all {
		if len(ids) == 0 {
			// Caller can see no systems: return an empty result rather
			// than a query that could only ever match nothing upstream.
			writeEmptyResult(w, emptyResultType)
			return
		}
		enforced, err := enforceSystemID(q, ids)
		if err != nil {
			// The query is the caller's own input; don't echo parser
			// internals back.
			writeJSONError(w, http.StatusBadRequest, "could not parse PromQL query")
			return
		}
		params.Set("query", enforced)
	}

	base := strings.TrimRight(h.UpstreamURL, "/")
	upstream, err := url.Parse(base + upstreamPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "invalid upstream URL")
		return
	}

	// Always POST the (possibly rewritten) parameters as a form body so a
	// long enforced query can't overflow a URL-length limit upstream.
	// Prometheus accepts POST form for both query and query_range.
	encoded := params.Encode()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream.String(), strings.NewReader(encoded))
	if err != nil {
		slog.Error("metrics: build upstream request", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "could not build upstream request")
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Upstream URL is operator-controlled via SW_PROMETHEUS_URL; the
	// request URL is the operator's prefix + a fixed path, and the query
	// has been parsed and re-rendered by the PromQL parser above. G704 is
	// a false positive.
	resp, err := h.client().Do(req) //nolint:gosec
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			writeJSONError(w, http.StatusGatewayTimeout, "upstream timed out")
			return
		}
		// Don't surface the raw transport error (it can carry the
		// internal Prometheus address); log it for the operator instead.
		slog.Warn("metrics: upstream request failed", "err", err)
		writeJSONError(w, http.StatusBadGateway, "upstream request failed")
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

// writeEmptyResult emits a well-formed empty Prometheus query response.
// resultType matches what the matching endpoint would have returned
// ("vector" for instant queries, "matrix" for range queries).
func writeEmptyResult(w http.ResponseWriter, resultType string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// resultType is a fixed internal constant, never user input.
	_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":%q,"result":[]}}`, resultType)
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
