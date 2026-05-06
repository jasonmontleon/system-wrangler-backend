// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"cat-wrangler-backend/internal/inventory"
)

func TestHandleHealth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	handleHealth(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
}

func TestServerRoutesHealth(t *testing.T) {
	srv := httptest.NewServer(withLogging(newMux(inventory.NewMemStore())))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != `{"status":"ok"}` {
		t.Errorf("body = %q", string(body))
	}
}

func TestServerRoutesHostsList(t *testing.T) {
	srv := httptest.NewServer(withLogging(newMux(inventory.NewMemStore())))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/hosts")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
}

func TestEnvOr(t *testing.T) {
	tests := []struct {
		name string
		set  bool
		val  string
		want string
	}{
		{"unset returns default", false, "", "default"},
		{"empty returns default", true, "", "default"},
		{"set returns value", true, "set-value", "set-value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "CW_TEST_KEY_" + tt.name
			if tt.set {
				t.Setenv(key, tt.val)
			}
			if got := envOr(key, "default"); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSPAHandlerEmptyDist(t *testing.T) {
	// dist/ contains only .gitkeep in dev/test. Verify the handler handles this
	// gracefully (no panic) for both the root and unknown SPA paths.
	h := spaHandler()
	for _, path := range []string{"/", "/some/spa/route"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, path, nil)
			h.ServeHTTP(w, r)
			if w.Code == 0 {
				t.Error("no status written")
			}
		})
	}
}

func TestStatusWriterCapturesCode(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec, status: 200}
	sw.WriteHeader(http.StatusCreated)
	if sw.status != http.StatusCreated {
		t.Errorf("status field = %d, want %d", sw.status, http.StatusCreated)
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("underlying writer code = %d", rec.Code)
	}
}

func TestWithLoggingPassesThrough(t *testing.T) {
	called := false
	h := withLogging(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(w, r)

	if !called {
		t.Fatal("inner handler not called")
	}
	if w.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTeapot)
	}
}
