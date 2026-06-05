// SPDX-License-Identifier: Apache-2.0

package scrape

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/exporters"
	"system-wrangler-backend/internal/sshproxy"
	"system-wrangler-backend/internal/systems"
)

type fakeFetcher struct {
	body []byte
	err  error
}

func (f *fakeFetcher) FetchOverTunnel(_ context.Context, _, _ string, _ int, _ string) ([]byte, error) {
	return f.body, f.err
}

type errExporters struct {
	exporters.Store
	err error
}

func (e *errExporters) GetSystemExporter(string, string) (exporters.SystemExporter, error) {
	return exporters.SystemExporter{}, e.err
}

func newHandlerFixture(t *testing.T) (*Handler, *systems.SQLiteStore, *exporters.SQLiteStore) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "scrape.db")
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("database.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sysStore, err := systems.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("systems.NewSQLiteStore: %v", err)
	}
	expStore, err := exporters.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("exporters.NewSQLiteStore: %v", err)
	}
	h := &Handler{
		Exporters: expStore,
		Secret:    "test-secret",
	}
	return h, sysStore, expStore
}

func TestScrapeDisabledWithoutSecret(t *testing.T) {
	h := &Handler{Secret: ""}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/internal/scrape/sys/exp")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestScrapeRejectsMissingSecret(t *testing.T) {
	h, _, _ := newHandlerFixture(t)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/internal/scrape/sys/exp")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestScrapeRejectsWrongSecret(t *testing.T) {
	h, _, _ := newHandlerFixture(t)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/internal/scrape/sys/exp", nil)
	req.Header.Set(HeaderSecret, "wrong")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestScrapeAcceptsBearerSecret(t *testing.T) {
	h, _, _ := newHandlerFixture(t)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	// Bearer is accepted but the system isn't installed → 404, which
	// is past the auth gate (proves the bearer matched).
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/internal/scrape/sys/builtin.dnf.exporter", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (auth passed but not installed)", resp.StatusCode)
	}
}

func TestScrapeUnknownSystem(t *testing.T) {
	h, _, _ := newHandlerFixture(t)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/internal/scrape/missing/exp", nil)
	req.Header.Set(HeaderSecret, "test-secret")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestScrapeRemovedRow(t *testing.T) {
	h, sysStore, expStore := newHandlerFixture(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "x", Hostname: "x.example"})
	_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: exporters.StateRemoved, Port: 9100,
	})
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/internal/scrape/"+sys.ID+"/builtin.dnf.exporter", nil)
	req.Header.Set(HeaderSecret, "test-secret")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, body=%s", resp.StatusCode, body)
	}
}

func TestScrapeNilExporters(t *testing.T) {
	h := &Handler{Secret: "s"}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/internal/scrape/sys/exp", nil)
	req.Header.Set(HeaderSecret, "s")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestScrapeLookupInternalError(t *testing.T) {
	h := &Handler{
		Secret:    "s",
		Exporters: &errExporters{err: errors.New("db down")},
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/internal/scrape/sys/exp", nil)
	req.Header.Set(HeaderSecret, "s")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestScrapeNilProxy(t *testing.T) {
	h, sysStore, expStore := newHandlerFixture(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "x", Hostname: "x.example"})
	_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: exporters.StateRunning, Port: 9100,
	})
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/internal/scrape/"+sys.ID+"/builtin.dnf.exporter", nil)
	req.Header.Set(HeaderSecret, "test-secret")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestScrapeSuccessReturnsBody(t *testing.T) {
	h, sysStore, expStore := newHandlerFixture(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "x", Hostname: "x.example"})
	_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: exporters.StateRunning, Port: 9100,
	})
	want := []byte("# HELP up 1\nup 1\n")
	h.Proxy = &fakeFetcher{body: want}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/internal/scrape/"+sys.ID+"/builtin.dnf.exporter", nil)
	req.Header.Set(HeaderSecret, "test-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != string(want) {
		t.Errorf("body = %q, want %q", got, want)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestScrapeProxyErrorMappings(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"no-credentials", sshproxy.ErrNoCredentials, http.StatusFailedDependency},
		{"no-host-key", sshproxy.ErrNoHostKey, http.StatusFailedDependency},
		{"host-key-match", sshproxy.ErrHostKeyMatch, http.StatusFailedDependency},
		{"dial-timeout", sshproxy.ErrDialTimeout, http.StatusGatewayTimeout},
		{"upstream", sshproxy.ErrUpstream, http.StatusBadGateway},
		{"deadline", context.DeadlineExceeded, http.StatusGatewayTimeout},
		{"unknown", errors.New("boom"), http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, sysStore, expStore := newHandlerFixture(t)
			sys, _ := sysStore.Create(systems.SystemInput{Name: "x", Hostname: "x.example"})
			_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
				SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
				State: exporters.StateRunning, Port: 9100,
			})
			h.Proxy = &fakeFetcher{err: tc.err}
			mux := http.NewServeMux()
			h.Register(mux)
			srv := httptest.NewServer(mux)
			defer srv.Close()
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/internal/scrape/"+sys.ID+"/builtin.dnf.exporter", nil)
			req.Header.Set(HeaderSecret, "test-secret")
			resp, _ := http.DefaultClient.Do(req)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestScrapeZeroPort(t *testing.T) {
	h, sysStore, expStore := newHandlerFixture(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "x", Hostname: "x.example"})
	// No port → install never completed; treat as 503.
	_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.dnf.exporter",
		State: exporters.StateRunning, Port: 0,
	})
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/internal/scrape/"+sys.ID+"/builtin.dnf.exporter", nil)
	req.Header.Set(HeaderSecret, "test-secret")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

func TestScrapeFailedLogsThroughInjectedLogger(t *testing.T) {
	h, sysStore, expStore := newHandlerFixture(t)
	sys, _ := sysStore.Create(systems.SystemInput{Name: "nb", Hostname: "nb.example"})
	_ = expStore.UpsertSystemExporter(exporters.SystemExporter{
		SystemID: sys.ID, ExporterID: "builtin.pkgin.exporter",
		State: exporters.StateInstalled, Port: 9100,
	})
	// A generic proxy error hits the default branch → 502 + "scrape failed".
	h.Proxy = &fakeFetcher{err: errors.New("connection refused")}
	var buf bytes.Buffer
	h.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})).
		With("component", "scrape")

	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet,
		srv.URL+"/internal/scrape/"+sys.ID+"/builtin.pkgin.exporter", nil)
	req.Header.Set(HeaderSecret, "test-secret")
	resp, _ := http.DefaultClient.Do(req)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatalf("decode log %q: %v", buf.String(), err)
	}
	if rec["component"] != "scrape" {
		t.Errorf("component = %v, want scrape", rec["component"])
	}
	if rec["msg"] != "scrape failed" {
		t.Errorf("msg = %v, want \"scrape failed\"", rec["msg"])
	}
}
