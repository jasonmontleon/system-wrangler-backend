// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"system-wrangler-backend/internal/systems"
)

// fakeProm stands in for the sibling Prometheus container in tests.
func fakeProm(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func TestQueryForwardsToUpstream(t *testing.T) {
	prom := fakeProm(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			t.Errorf("path = %q, want /api/v1/query", r.URL.Path)
		}
		if r.URL.Query().Get("query") != "node_load1" {
			t.Errorf("query param = %q", r.URL.Query().Get("query"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	})
	h := &Handler{
		UpstreamURL: prom.URL,
		CanRead:     func(context.Context) bool { return true },
	}
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
	var seenPath string
	var seenQuery string
	prom := fakeProm(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	})
	h := &Handler{UpstreamURL: prom.URL, CanRead: func(context.Context) bool { return true }}
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
	if !strings.Contains(seenQuery, "step=15") {
		t.Errorf("upstream query = %q", seenQuery)
	}
}

func TestForwardWhenForbidden(t *testing.T) {
	prom := fakeProm(t, func(http.ResponseWriter, *http.Request) {
		t.Error("upstream must not be called when CanRead returns false")
	})
	h := &Handler{
		UpstreamURL: prom.URL,
		CanRead:     func(context.Context) bool { return false },
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

func TestForwardWhenUpstreamUnset(t *testing.T) {
	h := &Handler{CanRead: func(context.Context) bool { return true }}
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
	h := &Handler{UpstreamURL: prom.URL, CanRead: func(context.Context) bool { return true }}
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
		body, _ := io.ReadAll(r.Body)
		seen = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})
	h := &Handler{UpstreamURL: prom.URL, CanRead: func(context.Context) bool { return true }}
	mux := http.NewServeMux()
	h.Register(mux, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Post(srv.URL+"/api/metrics/query", "application/x-www-form-urlencoded", strings.NewReader("query=up"))
	defer func() { _ = resp.Body.Close() }()
	if seen != "query=up" {
		t.Errorf("upstream body = %q", seen)
	}
}

// Compile-time check that systems.Store is part of the test fixture
// dependency surface (not used here, but kept so the test file stays
// linked against the canonical store type for future tests).
var _ systems.Store = (*systems.SQLiteStore)(nil)
