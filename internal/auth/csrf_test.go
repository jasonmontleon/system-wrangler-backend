// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"system-wrangler-backend/internal/audit"
	"system-wrangler-backend/internal/database"
)

func newCSRFFixture(t *testing.T) (*audit.Store, http.Handler, *sql.DB) {
	t.Helper()
	db, err := database.Open("file:" + filepath.Join(t.TempDir(), "csrf.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	auditStore, err := audit.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	return auditStore, CSRF(auditStore)(next), db
}

func sessionCookie() *http.Cookie {
	return &http.Cookie{Name: CookieName, Value: "irrelevant"} //nolint:gosec // G124: test cookie sent in a request; server-side attributes don't apply.
}

func TestCSRF_PassesSafeMethods(t *testing.T) {
	_, h, _ := newCSRFFixture(t)
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(m, "/api/admin/users", nil)
		req.Host = "sw.local"
		req.AddCookie(sessionCookie())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", m, rec.Code)
		}
	}
}

func TestCSRF_PassesExemptPaths(t *testing.T) {
	_, h, _ := newCSRFFixture(t)
	for _, p := range []string{"/api/auth/setup", "/api/auth/login"} {
		req := httptest.NewRequest(http.MethodPost, p, nil)
		req.Host = "sw.local"
		// Exempt paths get a pass even if there is a session cookie
		// and no Origin/header — the design depends on the fact
		// that they are unauthenticated by construction.
		req.AddCookie(sessionCookie())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", p, rec.Code)
		}
	}
}

func TestCSRF_BypassesNonCookieAuth(t *testing.T) {
	_, h, _ := newCSRFFixture(t)
	// No session cookie, no Origin, no header. Future Bearer-token
	// callers look exactly like this.
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users", nil)
	req.Host = "sw.local"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (bypass for non-cookie auth)", rec.Code)
	}
}

func TestCSRF_PassesSameOriginWithHeader(t *testing.T) {
	_, h, _ := newCSRFFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users", nil)
	req.Host = "sw.local"
	req.Header.Set("Origin", "https://sw.local")
	req.Header.Set(CSRFHeader, CSRFHeaderValue)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestCSRF_DenialPaths(t *testing.T) {
	tests := []struct {
		name       string
		origin     string
		referer    string
		header     string
		wantReason string
	}{
		{
			name:       "origin mismatch",
			origin:     "https://evil.example",
			header:     CSRFHeaderValue,
			wantReason: "origin_mismatch",
		},
		{
			name:       "referer fallback mismatch",
			referer:    "https://evil.example/some/path",
			header:     CSRFHeaderValue,
			wantReason: "referer_mismatch",
		},
		{
			name:       "origin and referer absent",
			header:     CSRFHeaderValue,
			wantReason: "origin_and_referer_absent",
		},
		{
			name:       "header missing",
			origin:     "https://sw.local",
			wantReason: "header_missing",
		},
		{
			name:       "header wrong value",
			origin:     "https://sw.local",
			header:     "nope",
			wantReason: "header_missing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditStore, h, _ := newCSRFFixture(t)
			req := httptest.NewRequest(http.MethodPost, "/api/admin/users", nil)
			req.Host = "sw.local"
			req.AddCookie(sessionCookie())
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			if tt.header != "" {
				req.Header.Set(CSRFHeader, tt.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			recs, _, err := auditStore.ListQuery(audit.Query{Action: "csrf.denied", Limit: 5})
			if err != nil {
				t.Fatalf("audit list: %v", err)
			}
			if len(recs) == 0 {
				t.Fatal("no csrf.denied audit row")
			}
			row := recs[0]
			if row.Outcome != audit.Denied {
				t.Errorf("audit outcome = %s, want denied", row.Outcome)
			}
			gotReason, _ := row.Detail["reason"].(string)
			if gotReason != tt.wantReason {
				t.Errorf("audit reason = %q, want %q", gotReason, tt.wantReason)
			}
			if got, _ := row.Detail["path"].(string); got != "/api/admin/users" {
				t.Errorf("audit path = %q, want /api/admin/users", got)
			}
		})
	}
}

func TestCSRF_PassesRefererFallback(t *testing.T) {
	_, h, _ := newCSRFFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users", nil)
	req.Host = "sw.local"
	req.Header.Set("Referer", "https://sw.local/dashboard")
	req.Header.Set(CSRFHeader, CSRFHeaderValue)
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestCSRF_SecFetchSiteSoftAssertion(t *testing.T) {
	// A bad Sec-Fetch-Site value should warn-but-not-block when
	// the other checks pass.
	_, h, _ := newCSRFFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users", nil)
	req.Host = "sw.local"
	req.Header.Set("Origin", "https://sw.local")
	req.Header.Set(CSRFHeader, CSRFHeaderValue)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (sec-fetch-site is soft)", rec.Code)
	}
}

func TestCSRF_NilAuditDoesNotPanic(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := CSRF(nil)(next)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users", nil)
	req.Host = "sw.local"
	req.AddCookie(sessionCookie())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestOriginMatchesHost(t *testing.T) {
	tests := []struct {
		name string
		val  string
		host string
		want bool
	}{
		{"exact match https", "https://sw.local", "sw.local", true},
		{"exact match http", "http://sw.local", "sw.local", true},
		{"port match", "https://sw.local:8443", "sw.local:8443", true},
		{"port mismatch", "https://sw.local:8443", "sw.local:443", false},
		{"different host", "https://evil.example", "sw.local", false},
		{"empty origin", "", "sw.local", false},
		{"referer with path", "https://sw.local/x/y", "sw.local", true},
		{"unparseable returns false", "://broken", "sw.local", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := originMatchesHost(tt.val, tt.host); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
