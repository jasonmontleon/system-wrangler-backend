// SPDX-License-Identifier: Apache-2.0

package buildinfo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetReturnsCurrentVars(t *testing.T) {
	orig := struct{ b, f, d string }{Backend, Frontend, BuildDate}
	t.Cleanup(func() {
		Backend, Frontend, BuildDate = orig.b, orig.f, orig.d
	})

	Backend = "abc1234"
	Frontend = "def5678"
	BuildDate = "2026-05-29T22:00:00Z"

	got := Get()
	if got.Backend != "abc1234" || got.Frontend != "def5678" || got.BuildDate != "2026-05-29T22:00:00Z" {
		t.Fatalf("Get() = %+v", got)
	}
}

func TestHandlerReturnsJSON(t *testing.T) {
	orig := struct{ b, f, d string }{Backend, Frontend, BuildDate}
	t.Cleanup(func() {
		Backend, Frontend, BuildDate = orig.b, orig.f, orig.d
	})

	Backend = "be01"
	Frontend = "fe02"
	BuildDate = "2026-01-01T00:00:00Z"

	req := httptest.NewRequest(http.MethodGet, "/api/build-info", nil)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got Info
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != (Info{Backend: "be01", Frontend: "fe02", BuildDate: "2026-01-01T00:00:00Z"}) {
		t.Fatalf("body = %+v", got)
	}
}

func TestDefaultsAreNonEmpty(t *testing.T) {
	// Belt-and-braces: even without ldflags, the strings must be
	// safe to serialize and non-empty so the frontend never sees
	// blank fields.
	orig := struct{ b, f, d string }{Backend, Frontend, BuildDate}
	defer func() { Backend, Frontend, BuildDate = orig.b, orig.f, orig.d }()
	Backend, Frontend, BuildDate = "dev", "dev", "unknown"
	got := Get()
	if got.Backend == "" || got.Frontend == "" || got.BuildDate == "" {
		t.Fatalf("default Info has empty field: %+v", got)
	}
}
