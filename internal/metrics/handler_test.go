// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"system-wrangler-backend/internal/systems"
)

// allowAll grants unconstrained access (any global role), so queries are
// forwarded without rewriting.
func allowAll(context.Context) (bool, []string, bool) { return true, nil, true }

// upstreamForm reads the form parameters the handler POSTed to the fake
// Prometheus. The handler always forwards as an x-www-form-urlencoded
// body, so the params live there rather than on the URL.
func upstreamForm(t *testing.T, r *http.Request) url.Values {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read upstream body: %v", err)
	}
	v, err := url.ParseQuery(string(b))
	if err != nil {
		t.Fatalf("parse upstream body: %v", err)
	}
	return v
}

// fakeProm stands in for the sibling Prometheus container in tests.
func fakeProm(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestDefaultUpstreamURLIsLoopback(t *testing.T) {
	if DefaultUpstreamURL != "http://127.0.0.1:9090" {
		t.Errorf("DefaultUpstreamURL = %q, want http://127.0.0.1:9090", DefaultUpstreamURL)
	}
}

func TestQueryForwardsToUpstream(t *testing.T) {
	prom := fakeProm(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Errorf("path = %q, want /api/v1/query", r.URL.Path)
		}
		if got := upstreamForm(t, r).Get("query"); got != "node_load1" {
			t.Errorf("query param = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	})
	h := &Handler{UpstreamURL: prom.URL, AllowedSystems: allowAll}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/metrics/query?query=node_load1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "success" {
		t.Errorf("body = %v", body)
	}
}

func TestQueryRangeForwardsParams(t *testing.T) {
	var seenPath, seenStep string
	prom := fakeProm(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenStep = upstreamForm(t, r).Get("step")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	})
	h := &Handler{UpstreamURL: prom.URL, AllowedSystems: allowAll}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/metrics/query_range?query=up&start=1&end=2&step=15")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if seenPath != "/api/v1/query_range" {
		t.Errorf("upstream path = %q", seenPath)
	}
	if seenStep != "15" {
		t.Errorf("upstream step = %q, want 15", seenStep)
	}
}

func TestForwardWhenForbidden(t *testing.T) {
	prom := fakeProm(t, func(http.ResponseWriter, *http.Request) {
		t.Error("upstream must not be called when scope resolution fails")
	})
	h := &Handler{
		UpstreamURL:    prom.URL,
		AllowedSystems: func(context.Context) (bool, []string, bool) { return false, nil, false },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/metrics/query?query=up")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// TestScopedQueryIsRewritten verifies a group-scoped caller's query reaches
// Prometheus constrained to their visible system_ids, regardless of what
// the caller asked for.
func TestScopedQueryIsRewritten(t *testing.T) {
	var seenQuery string
	prom := fakeProm(t, func(w http.ResponseWriter, r *http.Request) {
		seenQuery = upstreamForm(t, r).Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	})
	h := &Handler{
		UpstreamURL:    prom.URL,
		AllowedSystems: func(context.Context) (bool, []string, bool) { return false, []string{"sys-a", "sys-b"}, true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	// The caller tries to read a system outside their scope.
	resp, _ := http.Get(srv.URL + `/api/metrics/query?query=up{system_id="sys-z"}`)
	defer func() { _ = resp.Body.Close() }()
	if !strings.Contains(seenQuery, `system_id=~"sys-a|sys-b"`) {
		t.Errorf("scope matcher not injected: %q", seenQuery)
	}
	if !strings.Contains(seenQuery, `system_id="sys-z"`) {
		t.Errorf("caller's own matcher should be preserved (and intersect to empty): %q", seenQuery)
	}
}

// TestZeroVisibilityShortCircuits verifies a caller who can see no systems
// gets an empty result without any request reaching Prometheus.
func TestZeroVisibilityShortCircuits(t *testing.T) {
	prom := fakeProm(t, func(http.ResponseWriter, *http.Request) {
		t.Error("upstream must not be called when the caller has zero visible systems")
	})
	h := &Handler{
		UpstreamURL:    prom.URL,
		AllowedSystems: func(context.Context) (bool, []string, bool) { return false, nil, true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/metrics/query?query=up")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []any  `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "success" || body.Data.ResultType != "vector" || len(body.Data.Result) != 0 {
		t.Errorf("unexpected empty body: %+v", body)
	}
}

// TestScopedInvalidQueryRejected verifies an unparseable query from a
// scope-constrained caller is rejected (and not forwarded).
func TestScopedInvalidQueryRejected(t *testing.T) {
	prom := fakeProm(t, func(http.ResponseWriter, *http.Request) {
		t.Error("upstream must not be called for an unparseable query")
	})
	h := &Handler{
		UpstreamURL:    prom.URL,
		AllowedSystems: func(context.Context) (bool, []string, bool) { return false, []string{"sys-a"}, true },
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/metrics/query?query=up{{{")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestMissingQueryRejected(t *testing.T) {
	prom := fakeProm(t, func(http.ResponseWriter, *http.Request) {
		t.Error("upstream must not be called when no query is supplied")
	})
	h := &Handler{UpstreamURL: prom.URL, AllowedSystems: allowAll}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/metrics/query")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestForwardWhenUpstreamUnset(t *testing.T) {
	h := &Handler{AllowedSystems: allowAll}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/metrics/query?query=up")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestForwardUpstreamFailure(t *testing.T) {
	prom := fakeProm(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"status":"error","error":"boom"}`))
	})
	h := &Handler{UpstreamURL: prom.URL, AllowedSystems: allowAll}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/metrics/query?query=up")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Pass-through: 500 from Prometheus becomes 500 to the client.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (passthrough)", resp.StatusCode)
	}
}

func TestPostForwardsBody(t *testing.T) {
	var seen string
	prom := fakeProm(t, func(w http.ResponseWriter, r *http.Request) {
		seen = upstreamForm(t, r).Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})
	h := &Handler{UpstreamURL: prom.URL, AllowedSystems: allowAll}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/api/metrics/query", "application/x-www-form-urlencoded", strings.NewReader("query=up"))
	defer func() { _ = resp.Body.Close() }()
	if seen != "up" {
		t.Errorf("upstream query = %q, want up", seen)
	}
}

// Compile-time check that systems.Store is part of the test fixture
// dependency surface (not used here, but kept so the test file stays
// linked against the canonical store type for future tests).
var _ systems.Store = (*systems.SQLiteStore)(nil)

func TestForwardInvalidUpstreamURL(t *testing.T) {
	h := &Handler{
		UpstreamURL:    "http://[::1:invalid", // bracket-mismatched URL fails url.Parse
		AllowedSystems: allowAll,
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/metrics/query?query=up")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestForwardUpstreamConnectionRefused(t *testing.T) {
	h := &Handler{
		UpstreamURL:    "http://127.0.0.1:1", // nothing listens on TCP/1
		AllowedSystems: allowAll,
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/metrics/query?query=up")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

func TestForwardUsesCustomClient(t *testing.T) {
	prom := fakeProm(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})
	custom := &http.Client{}
	h := &Handler{
		UpstreamURL:    prom.URL,
		Client:         custom,
		AllowedSystems: allowAll,
	}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/metrics/query?query=up")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
