// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSpecEmbedNonEmpty(t *testing.T) {
	if len(Spec) == 0 {
		t.Fatal("Spec is empty — //go:embed failed to pick up spec.yaml")
	}
	if !strings.HasPrefix(string(Spec), "openapi: 3.1") {
		t.Errorf("Spec does not start with the OpenAPI 3.1 marker; first 32 bytes = %q", string(Spec[:min(32, len(Spec))]))
	}
}

func TestHandlerRegistersBothRoutes(t *testing.T) {
	mux := http.NewServeMux()
	Handler{}.Register(mux)

	tests := []struct {
		path    string
		ctype   string
		bodyHas string
	}{
		{"/api/openapi.yaml", "text/plain; charset=utf-8", "openapi: 3.1"},
		{"/api/docs", "text/html; charset=utf-8", "redoc"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != tt.ctype {
				t.Errorf("content-type = %q, want %q", got, tt.ctype)
			}
			if !strings.Contains(rec.Body.String(), tt.bodyHas) {
				t.Errorf("body missing %q substring; first 80 chars = %q", tt.bodyHas, rec.Body.String()[:min(80, rec.Body.Len())])
			}
		})
	}
}
