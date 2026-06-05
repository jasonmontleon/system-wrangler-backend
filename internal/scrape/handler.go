// SPDX-License-Identifier: Apache-2.0

// Package scrape is the Prometheus-facing scrape endpoint. Prometheus
// fetches /internal/scrape/{system_id}/{exporter_id}; this handler
// SSH-tunnels to the host's localhost-bound exporter and returns the
// text-format body verbatim.
//
// The handler is gated by a shared-secret header. The deployment
// topology (pod-shared-localhost or compose-network) is expected to
// keep /internal/* off the user-facing surface, but the header is
// defence-in-depth so a misconfigured proxy doesn't leak metrics to
// an attacker on the wire.
package scrape

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"system-wrangler-backend/internal/exporters"
	"system-wrangler-backend/internal/router"
	"system-wrangler-backend/internal/sshproxy"
)

// validSecret returns true when r carries the secret in either the
// X-Sw-Internal-Secret header or a Bearer Authorization header.
// Constant-time compare keeps the auth check timing-side-channel
// friendly.
func validSecret(r *http.Request, want string) bool {
	if got := r.Header.Get(HeaderSecret); got != "" {
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return true
		}
	}
	auth := r.Header.Get("Authorization")
	if len(auth) > len(bearerPrefix) && strings.EqualFold(auth[:len(bearerPrefix)], bearerPrefix) {
		token := auth[len(bearerPrefix):]
		if subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// HeaderSecret is the request header carrying the shared secret.
// Prometheus's native `authorization` config writes the secret as a
// Bearer token, which we accept as the canonical form; the
// X-Sw-Internal-Secret variant is the convenience form for testing
// with curl.
const HeaderSecret = "X-Sw-Internal-Secret" //nolint:gosec // header name, not a credential value

// bearerPrefix is the lowercase prefix we match the Authorization
// header against.
const bearerPrefix = "bearer "

// Fetcher fetches a single path over an SSH tunnel to the system's
// loopback. *sshproxy.Proxy satisfies this; tests use a fake.
type Fetcher interface {
	FetchOverTunnel(ctx context.Context, systemID, addr string, port int, path string) ([]byte, error)
}

// Handler exposes the scrape endpoint.
type Handler struct {
	Proxy     Fetcher
	Exporters exporters.Store
	// Secret is the expected value of the HeaderSecret header. An
	// empty Secret disables the endpoint entirely (responds 503) so
	// a misconfigured deployment doesn't accidentally expose
	// authenticated-by-omission scrape access.
	Secret string
	// Logger receives this subsystem's structured logs. Nil falls back
	// to slog.Default(). Wired to logging.Component("scrape") in main.go
	// so the lines carry component="scrape" and obey the adjustable
	// level — the per-scrape "scrape failed" warning against an
	// unreachable host is the noisiest line on a large install.
	Logger *slog.Logger
}

func (h *Handler) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// Register attaches the route. No middleware — the secret check is
// inline so the public auth middleware doesn't apply (Prometheus has
// no cookie + we don't want to fold the internal endpoint into the
// session machinery).
func (h *Handler) Register(mux router.Mux) {
	mux.Handle("GET /internal/scrape/{system}/{exporter}", http.HandlerFunc(h.scrape))
}

func (h *Handler) scrape(w http.ResponseWriter, r *http.Request) {
	if h.Secret == "" {
		http.Error(w, "scrape endpoint disabled (SW_INTERNAL_SECRET not set)", http.StatusServiceUnavailable)
		return
	}
	if !validSecret(r, h.Secret) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if h.Exporters == nil {
		http.Error(w, "scrape handler not fully wired", http.StatusServiceUnavailable)
		return
	}

	systemID := r.PathValue("system")
	exporterID := r.PathValue("exporter")
	if systemID == "" || exporterID == "" {
		http.Error(w, "missing path parameters", http.StatusBadRequest)
		return
	}

	row, err := h.Exporters.GetSystemExporter(systemID, exporterID)
	if err != nil {
		if errors.Is(err, exporters.ErrNotFound) {
			http.Error(w, "exporter not installed on this system", http.StatusNotFound)
			return
		}
		http.Error(w, "lookup failed", http.StatusInternalServerError)
		h.logger().Error("scrape lookup", "err", err, "system_id", systemID, "exporter_id", exporterID) //nolint:gosec
		return
	}
	if row.State == exporters.StateRemoved {
		http.Error(w, "exporter has been removed from this system", http.StatusNotFound)
		return
	}
	if row.Port == 0 {
		http.Error(w, "exporter has no recorded port; rerun install or status", http.StatusServiceUnavailable)
		return
	}
	if h.Proxy == nil {
		http.Error(w, "sshproxy not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := h.Proxy.FetchOverTunnel(r.Context(), systemID, "127.0.0.1", row.Port, "/metrics")
	if err != nil {
		// Map proxy errors to HTTP statuses so Prometheus's scrape
		// log carries a useful reason. Avoid leaking system_id /
		// internal paths into the response body — Prometheus stores
		// the response on scrape failure.
		switch {
		case errors.Is(err, sshproxy.ErrNoCredentials):
			http.Error(w, "no credentials resolved for system", http.StatusFailedDependency)
		case errors.Is(err, sshproxy.ErrNoHostKey):
			http.Error(w, "no accepted host key for system", http.StatusFailedDependency)
		case errors.Is(err, sshproxy.ErrHostKeyMatch):
			http.Error(w, "host key mismatch", http.StatusFailedDependency)
		case errors.Is(err, sshproxy.ErrDialTimeout):
			http.Error(w, "SSH dial timed out", http.StatusGatewayTimeout)
		case errors.Is(err, sshproxy.ErrUpstream):
			http.Error(w, "exporter returned non-2xx", http.StatusBadGateway)
		case errors.Is(err, context.DeadlineExceeded):
			http.Error(w, "scrape timed out", http.StatusGatewayTimeout)
		default:
			http.Error(w, "scrape failed", http.StatusBadGateway)
			h.logger().Warn("scrape failed", "err", err, "system_id", systemID, "exporter_id", exporterID) //nolint:gosec
		}
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	// body is the Prometheus exposition format from the remote
	// exporter — text/plain, not HTML. Prometheus is the consumer
	// and does not render this content, so the XSS taint warning
	// is a false positive.
	_, _ = w.Write(body) //nolint:gosec // Prometheus text format to Prometheus consumer
}
