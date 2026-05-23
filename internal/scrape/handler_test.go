// SPDX-License-Identifier: Apache-2.0

package scrape

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/database"
	"system-wrangler-backend/internal/exporters"
	"system-wrangler-backend/internal/systems"
)

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
